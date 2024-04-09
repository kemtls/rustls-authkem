use super::{
    common::ServerCertDetails,
    hs::{self, ClientContext},
    tls13::ExpectCertificate,
    ClientConnectionData,
};
use crate::{
    client::tls13::ExpectTraffic, common_state::State, conn::ConnectionRandoms, crypto::authkem::encapsulate, hash_hs::HandshakeHash, msgs::{
        base::Payload,
        handshake::{HandshakeMessagePayload, HandshakePayload, KemEncapsulationPayload},
        message::{Message, MessagePayload},
    }, tls13::authkem_key_schedule::KeyScheduleClientTraffic, verify, AlertDescription, ClientConfig, Error, HandshakeType, ProtocolVersion, Side, Tls13CipherSuite
};

use alloc::{boxed::Box, sync::Arc};
use log::warn;
use pki_types::ServerName;
use subtle::ConstantTimeEq;

pub(super) struct AuthKEMExpectCertificate {
    pub(super) state: ExpectCertificate,
    pub(super) cert_verified: verify::ServerCertVerified,
}

impl AuthKEMExpectCertificate {
    pub(super) fn into_expect_ciphertext_or_finished<'m>(
        self,
        server_cert: ServerCertDetails<'m>,
        cx: &mut ClientContext<'_>,
    ) -> hs::NextStateOrError<'m> {
        let mut state = self.state;

        let (ct, ss) = encapsulate(&server_cert.cert_chain[0], &state.config.provider.signature_verification_algorithms.all, b"server authentication")?;

        let ciphertext_message = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::KemEncapsulation,
                payload: HandshakePayload::KemEncapsulation(KemEncapsulationPayload::new_no_context(ct)),
            }),
        };
        state
            .transcript
            .add_message(&ciphertext_message);
        cx.common
            .send_msg(ciphertext_message, true);

        warn!("client auth ss = {:?}", ss);

        let key_schedule = state
            .key_schedule
            .into_authkem_authed_handshake(
                &ss,
                &*state.config.key_log,
                state.transcript.current_hash(),
                cx.common,
                &state.randoms.client,
            );
        cx.common.peer_certificates = Some(server_cert.cert_chain.into_owned());

        if state.client_auth.is_some() {
            unimplemented!()
        } else {
            let key_schedule = key_schedule.into_key_schedule_main_secret(None);

            // emit finished
            let verify_data = key_schedule.sign_client_finish(&state.transcript.current_hash());
            let verify_data_payload = Payload::new(verify_data.as_ref());

            let m = Message {
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::handshake(HandshakeMessagePayload {
                    typ: HandshakeType::Finished,
                    payload: HandshakePayload::Finished(verify_data_payload),
                }),
            };

            state.transcript.add_message(&m);
            cx.common.send_msg(m, true);
            // send client data

            /* Now move to our application traffic keys. */
            cx.common.check_aligned_handshake()?;

            let key_schedule = key_schedule.into_client_traffic(
                state.transcript.current_hash(),
                &*state.config.key_log,
                &state.randoms.client,
                Side::Client,
                cx.common,
            );

            cx.common
                .start_traffic(&mut cx.sendable_plaintext);

            // construct struct
            Ok(Box::new(ExpectAuthKEMFinished {
                key_schedule,
                transcript: state.transcript,
                server_name: state.server_name,
                config: state.config,
                randoms: state.randoms,
                suite: state.suite,
                cert_verified: self.cert_verified,
            }))
        }
    }
}

struct ExpectAuthKEMFinished {
    server_name: ServerName<'static>,
    key_schedule: KeyScheduleClientTraffic,
    transcript: HandshakeHash,
    config: Arc<ClientConfig>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    cert_verified: verify::ServerCertVerified,
}

impl State<ClientConnectionData> for ExpectAuthKEMFinished {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut crate::common_state::Context<'_, ClientConnectionData>,
        m: Message<'m>,
    ) -> Result<Box<dyn State<ClientConnectionData> + 'm>, Error>
    where
        Self: 'm,
    {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let handshake_hash = st.transcript.current_hash();
        let expect_verify_data = st
            .key_schedule
            .sign_server_finish(&handshake_hash);

        let fin = match ConstantTimeEq::ct_eq(expect_verify_data.as_ref(), finished.bytes()).into()
        {
            true => verify::FinishedMessageVerified::assertion(),
            false => {
                return Err(cx
                    .common
                    .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
            }
        };

        st.transcript.add_message(&m);

        let key_schedule_traffic = st.key_schedule.into_traffic(
            Side::Client,
            st.transcript.current_hash(),
            cx.common,
            &*st.config.key_log,
            &st.randoms.client,
        );

        Ok(Box::new(ExpectTraffic {
            config: Arc::clone(&st.config),
            session_storage: Arc::clone(&st.config.resumption.store),
            server_name: st.server_name,
            suite: st.suite,
            transcript: st.transcript,
            key_schedule: key_schedule_traffic,
            _cert_verified: st.cert_verified,
            _sig_verified: verify::HandshakeSignatureValid::assertion(),
            _fin_verified: fin,
        }))
    }

    fn into_owned(self: Box<Self>) -> Box<dyn State<ClientConnectionData> + 'static> {
        self
    }
}

#![allow(unreachable_pub, unused_imports)]

use alloc::boxed::Box;
use alloc::sync::Arc;
use log::{trace, warn};
use subtle::ConstantTimeEq;

use crate::conn::ConnectionRandoms;
use crate::crypto::tls13::OkmBlock;
use crate::crypto::{hash, hmac};
use crate::msgs::base::Payload;
use crate::msgs::codec::Codec;
use crate::msgs::handshake::{
    HandshakeMessagePayload, NewSessionTicketExtension, NewSessionTicketPayloadTls13,
};
use crate::msgs::message::Message;
use crate::server::tls13::get_server_session_value;
use crate::sign::{Signer, SigningKey};
use crate::tls13::key_schedule::{self, KeySchedule, KeyScheduleTraffic, SecretKind};
use crate::{
    client, key_log, rand, verify, AlertDescription, CommonState, ContentType, Error, KeyLog,
    ProtocolVersion, Side,
};
use crate::{
    common_state::State, hash_hs::HandshakeHash, msgs::handshake::HandshakePayload,
    tls13::key_schedule::KeyScheduleHandshake, HandshakeType, ServerConfig, Tls13CipherSuite,
};

use crate::internal::msgs::message::MessagePayload;

use super::hs::ServerContext;
use super::tls13::ExpectTraffic;
use super::ServerConnectionData;

use crate::tls13::authkem_key_schedule::{
    KeyScheduleAuthenticatedHandshake, KeyScheduleMainSecret,
};

pub(crate) struct ExpectAuthKemCiphertext {
    pub config: Arc<ServerConfig>,
    pub transcript: HandshakeHash,
    pub server_signer: Box<dyn Signer>,
    pub suite: &'static Tls13CipherSuite,
    pub key_schedule: KeyScheduleHandshake,
    pub send_tickets: usize,
    pub client_auth: bool,
    pub randoms: ConnectionRandoms,
}

impl State<ServerConnectionData> for ExpectAuthKemCiphertext {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut crate::common_state::Context<'_, ServerConnectionData>,
        message: Message<'m>,
    ) -> Result<Box<dyn State<ServerConnectionData> + 'm>, Error>
    where
        Self: 'm,
    {
        let ctmsg = require_handshake_msg!(
            message,
            HandshakeType::KemEncapsulation,
            HandshakePayload::KemEncapsulation
        )?;
        // decapsulate
        let ciphertext = ctmsg.bytes();
        let ss = self
            .server_signer
            .decapsulate(ciphertext, b"server authentication")?;

        warn!("server auth ss = {:?}", ss);

        self.transcript.add_message(&message);

        if self.client_auth {
            unimplemented!()
        } else {
            Ok(self.into_expect_finished(&ss, cx))
        }
    }

    fn into_owned(self: Box<Self>) -> Box<dyn State<ServerConnectionData> + 'static> {
        Box::new(Self {
            config: self.config,
            transcript: self.transcript,
            suite: self.suite,
            server_signer: self.server_signer,
            key_schedule: self.key_schedule,
            send_tickets: self.send_tickets,
            client_auth: self.client_auth,
            randoms: self.randoms,
        })
    }
}

impl ExpectAuthKemCiphertext {
    fn into_expect_finished(
        self,
        ss: &[u8],
        cx: &mut crate::common_state::Context<'_, ServerConnectionData>,
    ) -> Box<ExpectAuthKEMFinished> {
        // upgrade to authenticated handshake secret
        let key_schedule = self
            .key_schedule
            .into_authkem_authed_handshake(
                &ss,
                &*self.config.key_log,
                self.transcript.current_hash(),
                cx.common,
                &self.randoms.client,
            )
            // no client auth shared secret
            .into_key_schedule_main_secret(None);

        Box::new(ExpectAuthKEMFinished {
            config: self.config,
            transcript: self.transcript,
            suite: self.suite,
            key_schedule,
            send_tickets: self.send_tickets,
            randoms: self.randoms,
        })
    }
}

pub(crate) struct ExpectAuthKEMFinished {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleMainSecret,
    send_tickets: usize,
    randoms: ConnectionRandoms,
}

impl State<ServerConnectionData> for ExpectAuthKEMFinished {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut crate::common_state::Context<'_, ServerConnectionData>,
        message: Message<'m>,
    ) -> Result<Box<dyn State<ServerConnectionData> + 'm>, Error>
    where
        Self: 'm,
    {
        let finished =
            require_handshake_msg!(message, HandshakeType::Finished, HandshakePayload::Finished)?;

        let handshake_hash = self.transcript.current_hash();
        let expect_verify_data = self
            .key_schedule
            .sign_client_finish(&handshake_hash);

        let fin = match ConstantTimeEq::ct_eq(expect_verify_data.as_ref(), finished.bytes()).into()
        {
            true => verify::FinishedMessageVerified::assertion(),
            false => {
                return Err(cx
                    .common
                    .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
            }
        };

        // Note: future derivations include Client Finished (and later server finished), for AuthKEM including
        // the application data keying! This is unlike TLS 1.3
        self.transcript.add_message(&message);

        cx.common.check_aligned_handshake()?;

        // switch keys
        let key_schedule = self.key_schedule.into_client_traffic(
            self.transcript.current_hash(),
            &*self.config.key_log,
            &self.randoms.client,
            Side::Server,
            cx.common,
        );

        let handshake_hash = self.transcript.current_hash();
        let verify_data = key_schedule.sign_server_finish(&handshake_hash);
        let verify_data_payload = Payload::new(verify_data.as_ref());

        let m = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::Finished,
                payload: HandshakePayload::Finished(verify_data_payload),
            }),
        };

        // Note: future derivations include Client Finished (and later server finished), for AuthKEM including
        // the application data keying! This is unlike TLS 1.3
        self.transcript.add_message(&m);

        cx.common.send_msg(m, true);

        // switch keys again
        let key_schedule_traffic = key_schedule.into_traffic(
            Side::Server,
            self.transcript.current_hash(),
            cx.common,
            &*self.config.key_log,
            &self.randoms.client,
        );

        for _ in 0..self.send_tickets {
            Self::emit_ticket(
                &self.transcript,
                self.suite,
                cx,
                &key_schedule_traffic,
                &self.config,
            )?;
        }

        // Application data may now flow
        cx.common
            .start_traffic(&mut cx.sendable_plaintext);

        Ok(Box::new(ExpectTraffic {
            key_schedule: key_schedule_traffic,
            _fin_verified: fin,
        }))
    }

    fn into_owned(self: Box<Self>) -> super::hs::NextState<'static> {
        self
    }
}

impl ExpectAuthKEMFinished {
    // copied from tls13.rs
    fn emit_ticket(
        transcript: &HandshakeHash,
        suite: &'static Tls13CipherSuite,
        cx: &mut ServerContext<'_>,
        key_schedule: &KeyScheduleTraffic,
        config: &ServerConfig,
    ) -> Result<(), Error> {
        let secure_random = config.provider.secure_random;
        let nonce = rand::random_vec(secure_random, 32)?;
        let age_add = rand::random_u32(secure_random)?;
        let plain = get_server_session_value(
            transcript,
            suite,
            key_schedule,
            cx,
            &nonce,
            config.current_time()?,
            age_add,
        )
        .get_encoding();

        let stateless = config.ticketer.enabled();
        let (ticket, lifetime) = if stateless {
            let ticket = match config.ticketer.encrypt(&plain) {
                Some(t) => t,
                None => return Ok(()),
            };
            (ticket, config.ticketer.lifetime())
        } else {
            let id = rand::random_vec(secure_random, 32)?;
            let stored = config
                .session_storage
                .put(id.clone(), plain);
            if !stored {
                trace!("resumption not available; not issuing ticket");
                return Ok(());
            }
            let stateful_lifetime = 24 * 60 * 60; // this is a bit of a punt
            (id, stateful_lifetime)
        };

        let mut payload = NewSessionTicketPayloadTls13::new(lifetime, age_add, nonce, ticket);

        if config.max_early_data_size > 0 {
            if !stateless {
                payload
                    .exts
                    .push(NewSessionTicketExtension::EarlyData(
                        config.max_early_data_size,
                    ));
            } else {
                // We implement RFC8446 section 8.1: by enforcing that 0-RTT is
                // only possible if using stateful resumption
                warn!("early_data with stateless resumption is not allowed");
            }
        }

        let m = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::NewSessionTicket,
                payload: HandshakePayload::NewSessionTicketTls13(payload),
            }),
        };

        trace!("sending new ticket {:?} (stateless: {})", m, stateless);
        cx.common.send_msg(m, true);
        Ok(())
    }
}

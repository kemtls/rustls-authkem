use crate::{
    crypto::{hash, hmac, tls13::OkmBlock},
    CommonState, KeyLog, Side,
};

use super::key_schedule::{self, KeySchedule, KeyScheduleTraffic, SecretKind};

pub(crate) struct KeyScheduleAuthenticatedHandshake {
    pub(crate) ks: KeySchedule,
}

impl KeyScheduleAuthenticatedHandshake {
    pub(crate) fn into_key_schedule_main_secret(
        mut self,
        ss: Option<&[u8]>,
    ) -> KeyScheduleMainSecret {
        // derive MS by inputting client auth shared secret
        if let Some(ss) = ss {
            self.ks.input_secret(ss);
        } else {
            self.ks.input_empty();
        }
        KeyScheduleMainSecret { ks: self.ks }
    }
}

pub(crate) struct KeyScheduleMainSecret {
    ks: KeySchedule,
}

impl KeyScheduleMainSecret {
    pub(crate) fn sign_client_finish(&self, hs_hash: &hash::Output) -> hmac::Tag {
        let hmac_key = key_schedule::hkdf_expand_label_block(&*self.ks.current, b"s finished", &[]);
        self.ks
            .suite
            .hkdf_provider
            .hmac_sign(&hmac_key, hs_hash.as_ref())
    }

    pub(crate) fn into_client_traffic(
        self,
        hs_hash: hash::Output,
        key_log: &dyn KeyLog,
        client_random: &[u8; 32],
        side: Side,
        common: &mut CommonState,
    ) -> KeyScheduleClientTraffic {
        let current_client_traffic_secret = self.ks.derive_logged_secret(
            SecretKind::ClientApplicationTrafficSecret,
            hs_hash.as_ref(),
            key_log,
            client_random,
        );

        match side {
            Side::Client => self
                .ks
                .set_encrypter(&current_client_traffic_secret, common),
            Side::Server => self
                .ks
                .set_decrypter(&current_client_traffic_secret, common),
        };

        KeyScheduleClientTraffic {
            ks: self.ks,
            current_client_traffic_secret,
        }
    }
}

pub(crate) struct KeyScheduleClientTraffic {
    ks: KeySchedule,
    current_client_traffic_secret: OkmBlock,
}

impl KeyScheduleClientTraffic {
    pub(crate) fn sign_server_finish(&self, hs_hash: &hash::Output) -> hmac::Tag {
        let hmac_key = key_schedule::hkdf_expand_label_block(&*self.ks.current, b"c finished", &[]);
        self.ks
            .suite
            .hkdf_provider
            .hmac_sign(&hmac_key, hs_hash.as_ref())
    }

    pub(crate) fn into_traffic(
        self,
        side: Side,
        hs_hash: hash::Output,
        common: &mut CommonState,
        key_log: &dyn KeyLog,
        client_random: &[u8; 32],
    ) -> KeyScheduleTraffic {
        let current_server_traffic_secret = self.ks.derive_logged_secret(
            SecretKind::ServerApplicationTrafficSecret,
            hs_hash.as_ref(),
            key_log,
            client_random,
        );
        match side {
            Side::Client => self
                .ks
                .set_decrypter(&current_server_traffic_secret, common),
            Side::Server => self
                .ks
                .set_encrypter(&current_server_traffic_secret, common),
        };

        KeyScheduleTraffic::new_from_ks_and_keys_authkem(
            self.ks,
            self.current_client_traffic_secret,
            current_server_traffic_secret,
            hs_hash,
            key_log,
            client_random,
        )
    }
}

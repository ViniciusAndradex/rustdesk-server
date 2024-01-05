use crate::database;
use hbb_common::{
    log,
    rendezvous_proto::*,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub static IP_CHANGE_DUR: u64 = 180;
pub static IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub static DAY_SECONDS: u64 = 3600 * 24;
pub static IP_BLOCK_DUR: u64 = 60;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct MacControlInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct MacControl {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) mac_id: String,
    pub(crate) allowed_id: String,
}

impl Default for MacControl {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            mac_id: String::new(),
            allowed_id: String::new()
        }
    }
}

pub(crate) type LockMacControl = Arc<RwLock<MacControl>>;

#[derive(Clone)]
pub(crate) struct MacControlMap {
    map: Arc<RwLock<HashMap<String, LockMacControl>>>,
    pub(crate) db: database::Database,
}

impl MacControlMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = std::env::var("DB_URL").unwrap_or({
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let mcm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(mcm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        mac_id: String,
        allowed_id: String,
        mac_control: LockMacControl,
        addr: SocketAddr,
    ) -> register_pk_response::Result {
        log::info!("mac update_pk {} {:?} {:?}", mac_id, addr, allowed_id);
        let (mac) = {
            let mut w = mac_control.write().await;
            w.socket_addr = addr;
            w.allowed_id = allowed_id;
            (
                w.mac_id.clone(),
            )
        };
        if mac.is_empty() {
            match self.db.insert_mac(&mac_id, &allowed_id).await {
                Err(err) => {
                    log::error!("db.insert_mac failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
                Ok(mac) => {
                    log::info!("mac inserted {:?}", mac_id);
                }
            }
        } else {
            if let Err(err) = self.db.update_mac(&mac_id, &allowed_id).await {
                log::error!("db.update_mac failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            log::info!("mac updated instead of insert");
        }
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, mac_id: &String) -> Option<LockMacControl> {
        let p = self.map.read().await.get(mac_id).cloned();
        if p.is_some() {
            return p;
        } else if let Ok(Some(v)) = self.db.get_mac_id(mac_id).await {
            let mac = MacControl {
                mac_id: v.mac_id,
                allowed_id: v.allowed_id,
                ..Default::default()
            };
            let mac_control = Arc::new(RwLock::new(mac));
            self.map.write().await.insert(mac_id.to_owned(), mac.clone());
            return Some(mac_control);
        }
        None
    }

    pub(crate) async fn get_allowed_id_with_mac_id(&self, mac_id: &String, allowed_id: &String) -> Option<LockMacControl> {
        if let Ok(Some(v)) = self.db.get_allowed_id_with_mac_id(mac_id, allowed_id).await {
            let mac = MacControl {
                mac_id: v.mac_id,
                allowed_id: v.allowed_id,
                ..Default::default()
            };
            let mac_control = Arc::new(RwLock::new(mac));
            self.map.write().await.insert(mac_id.to_owned(), mac.clone());
            return Some(mac_control);
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, mac_id: &String) -> LockMacControl {
        if let Some(p) = self.get(mac_id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(mac_id) {
            return p.clone();
        }
        let tmp = LockMacControl::default();
        w.insert(mac_id.to_owned(), tmp.clone());
        tmp
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, mac_id: &String) -> Option<LockMacControl> {
        self.map.read().await.get(mac_id).cloned()
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, mac_id: &String) -> bool {
        self.map.read().await.contains_key(mac_id)
    }
}

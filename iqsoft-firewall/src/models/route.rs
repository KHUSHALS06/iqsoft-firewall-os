use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_metric() -> i32 {
    100
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Route {
    pub id: Option<i64>,

    pub name: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    pub destination: String,

    pub gateway: Option<String>,

    pub interface_name: Option<String>,

    #[serde(default = "default_metric")]
    pub metric: i32,

    pub comment: Option<String>,
}

impl Route {
    pub fn is_default_route(&self) -> bool {
        self.destination == "0.0.0.0/0" || self.destination == "::/0"
    }
}

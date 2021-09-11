use std::collections::HashMap;
use std::rc::Rc;
use std::str::FromStr;

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use log::{debug, info};

use serde::Deserialize;

use bdk_cli::bdk;
use bdk_cli::{KeySubCommand, OfflineWalletSubCommand, OnlineWalletSubCommand, WalletOpts};

use bdk::bitcoin;
use bdk::blockchain::EsploraBlockchain;
use bdk::database::memory::MemoryDatabase;
use bdk::keys::{GeneratableDefaultOptions, GeneratedKey};
use bdk::miniscript;
use bdk::*;

use bitcoin::*;

use miniscript::descriptor::{Sh, Wsh};
use miniscript::policy::Concrete;
use miniscript::Descriptor;
use miniscript::TranslatePk;

use clap::AppSettings;
use structopt::StructOpt;

mod utils;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn init() {
    console_log::init_with_level(log::Level::Debug).unwrap();
    utils::set_panic_hook();

    info!("Initialization completed");
}

#[derive(Debug, StructOpt, Clone, PartialEq)]
#[structopt(name = "", setting = AppSettings::NoBinaryName)]
pub enum WalletCommand {
    #[structopt(flatten)]
    OnlineWalletSubCommand(OnlineWalletSubCommand),
    #[structopt(flatten)]
    OfflineWalletSubCommand(OfflineWalletSubCommand),
    #[structopt(flatten)]
    KeySubCommand(KeySubCommand),
}

#[wasm_bindgen]
pub struct WalletWrapper {
    wallet: Rc<Wallet<EsploraBlockchain, MemoryDatabase>>,
    wallet_opts: Rc<WalletOpts>,
}

#[wasm_bindgen]
impl WalletWrapper {
    #[wasm_bindgen(constructor)]
    pub async fn new(
        network: String,
        descriptor: String,
        change_descriptor: Option<String>,
        esplora: String,
    ) -> Result<WalletWrapper, String> {
        let network = match network.as_str() {
            "regtest" => Network::Regtest,
            "testnet" | _ => Network::Testnet,
        };

        debug!("descriptors: {:?} {:?}", descriptor, change_descriptor);

        let blockchain = EsploraBlockchain::new(&esplora, 20);
        let wallet = Wallet::new(
            descriptor.as_str(),
            change_descriptor.as_ref().map(|x| x.as_str()),
            network,
            MemoryDatabase::new(),
            blockchain,
        )
        .await
        .map_err(|e| format!("{:?}", e))?;

        Ok(WalletWrapper {
            wallet: Rc::new(wallet),
            wallet_opts: Rc::new(WalletOpts {
                wallet: "default".into(),
                verbose: true,
                descriptor,
                change_descriptor,
            }),
        })
    }

    #[wasm_bindgen]
    pub fn run(&self, line: String) -> Promise {
        let wallet = Rc::clone(&self.wallet);
        let wallet_opts = Rc::clone(&self.wallet_opts);

        future_to_promise(async move {
            let subcommand =
                WalletCommand::from_iter_safe(line.split(" ")).map_err(|e| e.to_string())?;

            let res = match subcommand {
                WalletCommand::OnlineWalletSubCommand(online_subcommand) => {
                    bdk_cli::handle_online_wallet_subcommand(&wallet, online_subcommand).await
                }
                WalletCommand::OfflineWalletSubCommand(offline_subcommand) => {
                    bdk_cli::handle_offline_wallet_subcommand(
                        &wallet,
                        &wallet_opts,
                        offline_subcommand,
                    )
                }
                WalletCommand::KeySubCommand(key_subcommand) => {
                    bdk_cli::handle_key_subcommand(wallet.network(), key_subcommand)
                }
            };

            let res = res
                .map(|json| json.to_string())
                .map_err(|e| format!("{:?}", e))?;

            Ok(res.into())
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Alias {
    GenWif,
    GenExt { extra: String },
    Existing { extra: String },
}

impl Alias {
    fn into_key(self) -> String {
        match self {
            Alias::GenWif => {
                let generated: GeneratedKey<bitcoin::PrivateKey, miniscript::Legacy> =
                    GeneratableDefaultOptions::generate_default().unwrap();

                let mut key = generated.into_key();
                key.network = Network::Testnet;

                key.to_wif()
            }
            Alias::GenExt { extra: path } => {
                let generated: GeneratedKey<
                    bitcoin::util::bip32::ExtendedPrivKey,
                    miniscript::Legacy,
                > = GeneratableDefaultOptions::generate_default().unwrap();

                let mut xprv = generated.into_key();
                xprv.network = Network::Testnet;

                format!("{}{}", xprv, path)
            }
            Alias::Existing { extra } => extra,
        }
    }
}

#[wasm_bindgen]
pub fn compile(policy: String, aliases: String, script_type: String) -> Promise {
    future_to_promise(async move {
        let aliases: HashMap<String, Alias> =
            serde_json::from_str(&aliases).map_err(|e| format!("{:?}", e))?;
        let aliases: HashMap<String, String> = aliases
            .into_iter()
            .map(|(k, v)| (k, v.into_key()))
            .collect();

        macro_rules! err_str {
            ($e:expr) => {
                $e.map_err(|e| format!("{:?}", e))
            };
        }

        let policy = err_str!(Concrete::<String>::from_str(&policy))?;

        let descriptor = match script_type.as_str() {
            "sh" => Descriptor::Sh(err_str!(Sh::new(err_str!(policy.compile())?))?),
            "wsh" => Descriptor::Wsh(err_str!(Wsh::new(err_str!(policy.compile())?))?),
            "sh-wsh" => Descriptor::Sh(err_str!(Sh::new_wsh(err_str!(policy.compile())?))?),
            _ => return Err("InvalidScriptType".into()),
        };

        let descriptor: Result<Descriptor<String>, String> = descriptor.translate_pk(
            |key| Ok(aliases.get(key).unwrap_or(key).into()),
            |key| Ok(aliases.get(key).unwrap_or(key).into()),
        );
        let descriptor = descriptor?;

        Ok(format!("{}", descriptor).into())
    })
}

#![forbid(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::unimplemented
)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use kcs_migrator::client::{KcsClient, Timeouts};
use kcs_migrator::{export, importer, users};

#[derive(Parser)]
#[command(
    name = "kcs-migrator",
    about = "Export and import KCS configuration bundles"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Export {
        #[arg(long, env = "KCS_URL")]
        url: String,
        #[arg(long, env = "KCS_TOKEN")]
        token: String,
        #[arg(long, default_value = ".")]
        output: PathBuf,
        #[arg(long)]
        no_verify_tls: bool,
        #[arg(long)]
        host_header: Option<String>,
        #[arg(long, default_value = "kcs")]
        namespace: String,
        #[arg(long, default_value = "kcs-postgresql")]
        users_pod_selector: String,
        #[arg(long)]
        skip_users: bool,
    },
    ImportBundle {
        bundle: PathBuf,
        #[arg(long, env = "KCS_URL")]
        url: String,
        #[arg(long, env = "KCS_TOKEN")]
        token: String,
        #[arg(long)]
        no_verify_tls: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Export {
            url,
            token,
            output,
            no_verify_tls,
            host_header,
            namespace,
            users_pod_selector,
            skip_users,
        } => {
            let verify_tls = !no_verify_tls;
            let (client, kcs) = KcsClient::detect(
                &url,
                &token,
                verify_tls,
                host_header.as_deref(),
                Timeouts::default(),
            )
            .await?;
            println!(
                "Source is KCS {kcs}, exporting via API{}.",
                client.api_version().prefix().trim_start_matches('/')
            );
            let bundle = export::export_all(&client, &output).await?;
            println!("Bundle exported to: {}", bundle.display());

            if !skip_users {
                match users::export_users_reference(&namespace, &bundle, &users_pod_selector) {
                    Ok(_) => println!("User reference exported successfully."),
                    Err(e) => eprintln!("Warning: Failed to export users: {e}"),
                }
            }
        }
        Commands::ImportBundle {
            bundle,
            url,
            token,
            no_verify_tls,
        } => {
            let verify_tls = !no_verify_tls;
            let (client, kcs) =
                KcsClient::detect(&url, &token, verify_tls, None, Timeouts::default()).await?;
            println!(
                "Target is KCS {kcs}, importing via API{}.",
                client.api_version().prefix().trim_start_matches('/')
            );
            importer::import_bundle(&client, &bundle).await?;
            println!("Import complete.");
        }
    }

    Ok(())
}

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use kcs_migrator::client::KcsClient;
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
            let client = KcsClient::new(&url, &token, verify_tls, host_header.as_deref())?;
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
            let client = KcsClient::new(&url, &token, verify_tls, None)?;
            importer::import_bundle(&client, &bundle).await?;
            println!("Import complete.");
        }
    }

    Ok(())
}

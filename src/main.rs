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
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use kcs_migrator::cli::ConnOpts;
use kcs_migrator::{export, importer, users};

#[derive(Parser)]
#[command(
    name = "kcs-migrator",
    version,
    about = "Export and import KCS configuration bundles"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Options for the `kubectl exec` user export, which is reference-only
/// and talks to the cluster rather than to the KCS API.
#[derive(Args)]
struct UserExportOpts {
    /// Kubernetes namespace holding the KCS release.
    #[arg(long, default_value = "kcs")]
    namespace: String,

    /// `StatefulSet` name of the KCS Postgres pod.
    #[arg(long, default_value = "kcs-postgresql")]
    users_pod_selector: String,

    /// Skip the `kubectl exec` user export step.
    #[arg(long)]
    skip_users: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Export KCS configuration to a timestamped bundle directory.
    Export {
        #[command(flatten)]
        conn: ConnOpts,

        /// Directory to write the bundle into.
        #[arg(long, default_value = ".")]
        output: PathBuf,

        #[command(flatten)]
        users: UserExportOpts,
    },

    /// Restore a bundle to a target KCS instance.
    ImportBundle {
        /// Path to the bundle directory.
        bundle: PathBuf,

        #[command(flatten)]
        conn: ConnOpts,

        /// Resolve and describe every call without sending a single write.
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Export {
            conn,
            output,
            users: user_opts,
        } => {
            let (client, resolved) = conn.connect().await?;
            println!("Source: {resolved}");

            let bundle = export::export_all(&client, &output).await?;
            println!("Bundle exported to: {}", bundle.display());

            if !user_opts.skip_users {
                match users::export_users_reference(
                    &user_opts.namespace,
                    &bundle,
                    &user_opts.users_pod_selector,
                ) {
                    Ok(_) => println!("User reference exported successfully."),
                    Err(e) => eprintln!("Warning: Failed to export users: {e}"),
                }
            }
        }
        Commands::ImportBundle {
            bundle,
            conn,
            dry_run,
        } => {
            let (client, resolved) = conn.connect().await?;
            let client = client.with_dry_run(dry_run);
            println!("Target: {resolved}");
            if dry_run {
                println!("DRY RUN: no write will be sent to the target.");
            }

            importer::import_bundle(&client, &bundle).await?;

            if dry_run {
                println!("Dry run complete. Nothing was written.");
            } else {
                println!("Import complete.");
            }
        }
    }

    Ok(())
}

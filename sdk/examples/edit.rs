/// demonstrate using the new Builder::edit() method.
use anyhow::Result;
use c2pa::{assertions::Action, Builder, Reader, Settings};
use clap::Parser;
use serde_json::json;

//     &toml::toml! {
//         [builder.actions.auto_created_action]
//         enabled = true
//         source_type = (DigitalSourceType::Empty.to_string())
//     }
//     .to_string(),
// )
// .unwrap();

#[derive(Parser)]
#[command(
    author = "Gavin Peacock <gpeacock@adobe.com>",
    about = "Show C2PA data for a file or sign an edited file with new actions.",
    arg_required_else_help = true
)]
struct Args {
    /// Source file path
    source: String,
    /// Destination file path (optional)
    dest: Option<String>,
    /// Settings file path
    #[arg(long)]
    settings: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Load default settings
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    // Load settings overrides
    if let Some(path) = &args.settings {
        Settings::from_file(path)?;
    };

    let reader = if let Some(dest_path) = &args.dest {
        let mut builder = Builder::edit();

        builder.add_action(Action::new("c2pa.published"))?;

        builder.add_action(json!({
            "action": "c2pa.edited",
            "description": "my special edits",
            "parameters": {
                "name": "any value"
            },
        }))?;

        builder.sign_file(&Settings::signer()?, &args.source, dest_path)?;

        Reader::from_file(dest_path)
    } else {
        Reader::from_file(&args.source)
    }?;
    println!("{reader}");
    Ok(())
}

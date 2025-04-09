use clap::Parser;

#[derive(clap::Parser)]
enum Cli {
    Create {
        /// Title of the note
        #[arg(short, long)]
        title: String,
        /// Content of the note
        #[arg(short, long)]
        content: String,
    },
    Delete {
        /// Key used to encrypt the note
        /// This is the key you used to encrypt the note
        /// You can get this key from the output of the create command
        #[arg(short, long)]
        input_key: String,
        /// Nonce used to encrypt the note
        /// This is the nonce you used to encrypt the note
        /// You can get this nonce from the output of the create command
        #[arg(short, long)]
        nonce: String,
        /// ID of the note
        #[arg(short, long)]
        id: String,
    },
    Read {
        /// Key used to encrypt the note
        /// This is the key you used to encrypt the note
        /// You can get this key from the output of the create command
        #[arg(short, long)]
        input_key: String,
        /// Nonce used to encrypt the note
        /// This is the nonce you used to encrypt the note
        /// You can get this nonce from the output of the create command
        #[arg(short, long)]
        nonce: String,
        /// ID of the note
        #[arg(short, long)]
        id: String,
    },
}

fn main() {
    let cli = Cli::parse();
}

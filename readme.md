# uplite

**uplite** is a lightweight and secure file server built in Rust.

It lets you upload, download, and manage files from any device including phones, tablets, and desktops using your browser.

## Overview

uplite is designed to provide a simple, self-contained solution for sharing files across devices. Whether you need to quickly share photos, documents, or other data, uplite offers an intuitive web interface for managing your files securely.

## Key Features

- **Multi device connectivity:** Access your file server from any device (phones, tablets, desktops) using any modern web browser.
- **Single binary deployment:** With embedded templates and assets, uplite requires no additional configuration files just the executable.
- **File uploads & downloads:** Easily upload multiple files at once, view detailed file information, download files, or delete files directly through your browser.


## Security Measures

- **Authentication:** Protect your file server with HTTP Basic Authentication.
- **Asset embedding:** Embedding all assets within the binary minimizes the risk of external tampering.
- **Input sanitization:** Uploaded filenames are cleaned to prevent path traversal and code injection.
- **Rate & size limiting:** Configurable limits on the number of files and maximum file size help prevent abuse.
- **Secure headers:** Default headers prevent caching and MIME type sniffing.

## Installation

You can install **uplite** directly using Cargo:

```bash
cargo install uplite
```

*(Ensure you have Rust installed via [rustup](https://rustup.rs/) before running this command.)*

## Building and Running Locally

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/gni/uplite-rust.git
   cd uplite-rust
   ```

2. **Build the Project:**

   ```bash
   cargo build --release
   ```

3. **Run the Server:**

   ```bash
   ./target/release/uplite --port 3000 --user admin --password secret --dir ./uploads --max-files 5 --max-size 10485760
   ```

   This command starts the server on port 3000 with the specified credentials and file upload settings.

## Command-line options

Below is a table with the available CLI options that you can use when running **uplite**:

| Option                | Description                                                       | Default Value        |
|-----------------------|-------------------------------------------------------------------|----------------------|
| `-P, --port`           | Port the server listens on.                                        | `58080`              |
| `-u, --user`           | Username for Basic Authentication.                                | `admin`              |
| `-p, --password`       | Password for Basic Authentication.                                | `password`           |
| `-d, --dir`            | Directory to store uploaded files.                                | `./`                 |
| `--max-files`          | Maximum number of files per upload.                               | `10`                 |
| `--max-size`           | Maximum allowed file size (in bytes).                             | `5 * 1024 * 1024 * 1024` (5 GB) |
| `--extensions`         | Comma-separated list of allowed file extensions (without dots).   | `""` (No restrictions)|


### Example commands

1. **Run with default options**

   ```bash
   uplite
   ```

2. **Specify a custom port**

   ```bash
   uplite --port 3000
   ```

3. **Set authentication credentials**

   ```bash
   uplite --user admin --password secret
   ```

4. **Define a custom upload directory**

   ```bash
   uplite --dir ./uploads
   ```

5. **Limit uploads (max files and size)**

   ```bash
   uplite --max-files 5 --max-size 10485760
   ```

6. **Allow specific file extensions**

   ```bash
   uplite --extensions jpg,png,gif,svg
   ```

7. **Combined example**

   ```bash
   uplite --port 3000 --user admin --password secret --dir ./uploads --max-files 5 --max-size 10485760 --extensions jpg,png,gif,svg
   ```

## Deployment

Since uplite embeds all its templates and static assets, deploying is as simple as copying the single executable to your target system. There is no need to set up or manage separate asset directories.

## Additional Information

A similar project exists as an npm module. Visit the [uplite (npm) repository](https://github.com/gni/uplite.git) for more details.

This repository specifically hosts the Rust version, and the compiled binary is named `uplite`.

## License

uplite is open source software licensed under the [MIT License](LICENSE).

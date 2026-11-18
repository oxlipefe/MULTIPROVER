//! Embebe en el binario el commit del árbol con el que se compiló.
//!
//! La evidencia tiene que nombrar el código que CORRIÓ, no el `HEAD` del árbol
//! en el momento de escribir el archivo: un binario viejo sobre un árbol nuevo
//! (un `target/` que no se reconstruyó) firmaría con un commit que no es el
//! suyo. Si no hay git, o el árbol no es un repositorio, el valor dice que no
//! se sabe en vez de inventar uno.

use std::path::Path;
use std::process::Command;

const SIN_COMMIT: &str = "desconocido (compilado sin git)";

fn commit_corto() -> Option<String> {
    let salida = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()?;
    if !salida.status.success() {
        return None;
    }
    let texto = String::from_utf8(salida.stdout).ok()?;
    let commit = texto.trim();
    let es_hexa = !commit.is_empty() && commit.chars().all(|c| c.is_ascii_hexdigit());
    es_hexa.then(|| commit.to_string())
}

fn main() {
    let commit = commit_corto().unwrap_or_else(|| SIN_COMMIT.to_string());
    println!("cargo:rustc-env=ZKVM_COMMIT={commit}");

    // Recompilar cuando se mueve `HEAD` o una rama: sin esto, el valor embebido
    // se quedaría con el commit del primer build.
    let git = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.git");
    for parte in ["HEAD", "refs", "packed-refs"] {
        let p = git.join(parte);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
}

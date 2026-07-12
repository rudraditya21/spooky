use crate::cli::Args;
use crate::io::load_release_index;
use crate::io::write_release_index;
use crate::report::ReleaseBaselineEntry;
use std::fs;
use std::path::PathBuf;

pub fn run_promotion(args: &Args) -> Result<(), String> {
    let release = args
        .promote_release
        .as_ref()
        .ok_or_else(|| "internal error: promote_release missing".to_string())?;

    let mut index = load_release_index(&args.baseline_index)?;

    let release_dir = PathBuf::from("bench").join("baselines").join(release);
    fs::create_dir_all(&release_dir).map_err(|err| {
        format!(
            "failed to create release baseline directory '{}': {err}",
            release_dir.display()
        )
    })?;

    if !args.promote_micro_report.exists() {
        return Err(format!(
            "micro report '{}' does not exist",
            args.promote_micro_report.display()
        ));
    }
    if !args.promote_macro_report.exists() {
        return Err(format!(
            "macro report '{}' does not exist",
            args.promote_macro_report.display()
        ));
    }

    let micro_dest = release_dir.join("micro.json");
    let macro_dest = release_dir.join("macro.json");

    fs::copy(&args.promote_micro_report, &micro_dest).map_err(|err| {
        format!(
            "failed to copy micro report '{}' -> '{}': {err}",
            args.promote_micro_report.display(),
            micro_dest.display()
        )
    })?;
    fs::copy(&args.promote_macro_report, &macro_dest).map_err(|err| {
        format!(
            "failed to copy macro report '{}' -> '{}': {err}",
            args.promote_macro_report.display(),
            macro_dest.display()
        )
    })?;

    let entry = ReleaseBaselineEntry {
        micro: micro_dest.to_string_lossy().to_string(),
        macro_report: macro_dest.to_string_lossy().to_string(),
    };
    index.releases.insert(release.clone(), entry);
    if args.set_current_release {
        index.current_release = release.clone();
    }

    write_release_index(&args.baseline_index, &index)?;

    println!(
        "Promoted release baseline '{}' (micro='{}', macro='{}')",
        release,
        micro_dest.display(),
        macro_dest.display()
    );

    Ok(())
}

//! Matjet e CU dhe gjenerimi i raportit `results/cu-report.{json,md}`.

use std::fmt::Write as _;

/// Një matje e vetme.
pub struct Measurement {
    pub name: &'static str,
    /// `None` = ende pa u matur.
    pub cu: Option<u64>,
    pub note: &'static str,
}

/// Kufijtë GO / NO-GO për `verify_full` (shih docs/HAPI-1-BRIEF.md).
pub fn verdict(total_cu: Option<u64>) -> &'static str {
    match total_cu {
        None => "PA MATJE",
        Some(c) if c <= 400_000 => "GO",
        Some(c) if c <= 1_000_000 => "GO me kujdes",
        Some(c) if c <= 1_400_000 => "Rishikim",
        Some(_) => "NO-GO",
    }
}

pub fn render_markdown(ms: &[Measurement], total: Option<u64>) -> String {
    let mut s = String::from("## Matjet e CU — zklogin-verifier\n\n| Matja | CU | Shënim |\n|---|---:|---|\n");
    for m in ms {
        let cu = m.cu.map(|c| c.to_string()).unwrap_or_else(|| "—".into());
        let _ = writeln!(s, "| `{}` | {} | {} |", m.name, cu, m.note);
    }
    let _ = writeln!(s, "\n**Vendimi:** {}\n", verdict(total));
    s
}

pub fn render_json(ms: &[Measurement], total: Option<u64>) -> String {
    let items: Vec<String> = ms
        .iter()
        .map(|m| {
            let cu = m.cu.map(|c| c.to_string()).unwrap_or_else(|| "null".into());
            format!("    {{ \"name\": \"{}\", \"cu\": {} }}", m.name, cu)
        })
        .collect();
    format!(
        "{{\n  \"verdict\": \"{}\",\n  \"measurements\": [\n{}\n  ]\n}}\n",
        verdict(total),
        items.join(",\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn thresholds() {
        assert_eq!(verdict(Some(350_000)), "GO");
        assert_eq!(verdict(Some(900_000)), "GO me kujdes");
        assert_eq!(verdict(Some(1_200_000)), "Rishikim");
        assert_eq!(verdict(Some(1_500_000)), "NO-GO");
        assert_eq!(verdict(None), "PA MATJE");
    }
}

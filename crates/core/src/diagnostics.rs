use crate::Severity;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub offset: Option<usize>,
    pub context: Option<String>,
}
impl Diagnostic {
    pub fn new(severity: Severity, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { severity, code: code.into(), message: message.into(), offset: None, context: None }
    }
    pub fn at(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiagnosticSet {
    items: Vec<Diagnostic>,
}
impl DiagnosticSet {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }
    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.items.push(diagnostic);
    }
    pub fn extend(&mut self, other: DiagnosticSet) {
        self.items.extend(other.items);
    }
    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|d| d.severity >= Severity::High)
    }
    pub fn highest(&self) -> Option<Severity> {
        self.items.iter().map(|d| d.severity).max()
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &Diagnostic> {
        self.items.iter()
    }
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        for item in &self.items {
            if let Some(offset) = item.offset {
                out.push_str(&format!("[{}] {} at {}: {}\n", item.severity.as_str(), item.code, offset, item.message));
            } else {
                out.push_str(&format!("[{}] {}: {}\n", item.severity.as_str(), item.code, item.message));
            }
            if let Some(ctx) = &item.context {
                out.push_str("  ");
                out.push_str(ctx);
                out.push('\n');
            }
        }
        out
    }
}

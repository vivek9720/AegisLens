#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleToken {
    Word(String),
    Quoted(String),
    LParen,
    RParen,
    Colon,
    Semicolon,
    Bang,
    BracketOpen,
    BracketClose,
    Comma,
}
pub fn lex_rule(input: &str) -> Vec<RuleToken> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            c if c.is_ascii_whitespace() => {}
            '(' => tokens.push(RuleToken::LParen),
            ')' => tokens.push(RuleToken::RParen),
            ':' => tokens.push(RuleToken::Colon),
            ';' => tokens.push(RuleToken::Semicolon),
            '!' => tokens.push(RuleToken::Bang),
            '[' => tokens.push(RuleToken::BracketOpen),
            ']' => tokens.push(RuleToken::BracketClose),
            ',' => tokens.push(RuleToken::Comma),
            '"' => {
                let mut value = String::new();
                while let Some(next) = chars.next() {
                    if next == '\\' {
                        if let Some(escaped) = chars.next() {
                            value.push(escaped);
                        }
                    } else if next == '"' {
                        break;
                    } else {
                        value.push(next);
                    }
                }
                tokens.push(RuleToken::Quoted(value));
            }
            _ => {
                let mut word = String::new();
                word.push(ch);
                while let Some(peek) = chars.peek() {
                    if peek.is_ascii_whitespace() || matches!(peek, '(' | ')' | ':' | ';' | '!' | '[' | ']' | ',' | '"') {
                        break;
                    }
                    word.push(*peek);
                    chars.next();
                }
                tokens.push(RuleToken::Word(word));
            }
        }
    }
    tokens
}

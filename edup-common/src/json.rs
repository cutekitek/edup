//! Конфигурации клиента и сервера: JSON с комментариями `//` и `/* */`.

use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{
    string::{String, ToString},
    vec::Vec,
};

/// Разбирает конфигурацию. Текст ошибки содержит строку и столбец, но не пароли:
/// serde включает в сообщение значение поля неверного типа.
pub fn parse<T: DeserializeOwned>(input: &str) -> Result<T, String> {
    let text = strip_comments(input)?;
    serde_json::from_str(&text).map_err(|error| {
        let mut message = error.to_string();
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            let mut secrets = Vec::new();
            passwords(&value, &mut secrets);
            for secret in secrets.iter().filter(|s| !s.is_empty()) {
                message = message.replace(secret.as_str(), "<redacted>");
            }
        }
        message
    })
}

fn passwords(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                match value {
                    Value::String(s) if key == "password" => out.push(s.clone()),
                    Value::Number(n) if key == "password" => out.push(n.to_string()),
                    _ => passwords(value, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|v| passwords(v, out)),
        _ => {}
    }
}

/// Заменяет комментарии пробелами, сохраняя переводы строк, чтобы позиции
/// в ошибках serde_json совпадали с исходным файлом.
fn strip_comments(input: &str) -> Result<String, String> {
    let mut bytes = input
        .strip_prefix('\u{feff}')
        .unwrap_or(input)
        .as_bytes()
        .to_vec();
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1)) {
            (b'"', _) => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            (b'/', Some(b'/')) => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    bytes[i] = b' ';
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                let start = i;
                i += 2;
                while i < bytes.len()
                    && !(bytes[i - 1] == b'*' && bytes[i] == b'/' && i > start + 2)
                {
                    i += 1;
                }
                if i >= bytes.len() {
                    return Err("unterminated /* comment".into());
                }
                for b in &mut bytes[start..=i] {
                    if *b != b'\n' {
                        *b = b' ';
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    // Only whole comments, including any multibyte characters, were replaced.
    String::from_utf8(bytes).map_err(|_| "invalid UTF-8".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        url: String,
        password: String,
        n: i64,
    }

    #[test]
    fn comments_are_ignored_outside_strings() {
        let value: Sample = parse(
            "\u{feff}{ // комментарий\n \"url\": \"http://x/*y*/\", /* a\n b */ \"password\": \"p//\\\"q\",\n\"n\": -9223372036854775808 /**/ }",
        )
        .unwrap();
        assert_eq!(value.url, "http://x/*y*/");
        assert_eq!(value.password, "p//\"q");
        assert_eq!(value.n, i64::MIN);
        assert!(parse::<Sample>("{ /* open ").is_err());
        assert!(parse::<Sample>("{ /*/ }").is_err());
    }

    #[test]
    fn errors_have_position_and_no_passwords() {
        let error =
            parse::<Sample>("{\n\"url\": \"u\",\n\"n\": \"hunter2\",\n\"password\": \"hunter2\"}")
                .unwrap_err();
        assert!(!error.contains("hunter2"), "{error}");
        assert!(error.contains("line 3"), "{error}");
        let error =
            parse::<Sample>("{\"url\": \"u\", \"n\": 1, \"password\": 5, \"x\": 5}").unwrap_err();
        assert!(error.contains("expected a string"), "{error}");
        let error =
            parse::<Sample>("{\"url\": \"u\", \"n\": 1, \"password\": \"s\", \"extra\": 1}")
                .unwrap_err();
        assert!(error.contains("unknown field `extra`"), "{error}");
    }
}

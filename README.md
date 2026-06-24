# 🔐 Password Strength Analyzer

A clean, fully client-side password strength analyzer with real-time feedback, entropy calculation, a password generator, and session-based reuse detection.

**No data ever leaves your browser.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black)

## ✨ Features

- **Real-time strength meter** — scores passwords as you type (Weak → Fair → Strong → Very Strong)
- **Entropy calculation** — measures bits of entropy based on character pool size
- **8-point checklist** — length, uppercase, lowercase, digits, symbols, sequential patterns, repeated chars
- **Crack time estimate** — based on a 10 billion guesses/second offline attack rate
- **Common password detection** — flags widely-known passwords instantly
- **Tailored suggestions** — tells you exactly what to fix, not generic advice
- **Password generator** — random passwords or memorable passphrases, fully configurable
- **Session history** — tracks analyzed passwords (masked) for reuse detection
- **Dark mode** — respects system preference via `prefers-color-scheme`
- **Accessible** — ARIA labels, roles, and live regions throughout

## 🚀 Getting Started

No build step, no dependencies, no server required.

```bash
git clone https://github.com/YOUR_USERNAME/password-strength-analyzer.git
cd password-strength-analyzer
open index.html        # macOS
# or just double-click index.html on Windows/Linux
```

Or deploy instantly to **GitHub Pages**, **Netlify**, or **Vercel** — it's just static files.

## 📁 Project Structure

```
password-strength-analyzer/
├── index.html    # Markup and layout
├── style.css     # All styles (light + dark mode)
├── analyzer.js   # All logic (analysis, generation, history)
└── README.md
```

## 🧠 How Strength is Scored

| Score | Label | Criteria |
|-------|-------|----------|
| 1 | Weak | Entropy < 28 bits, fewer than 3 checks passed, or a common password |
| 2 | Fair | Entropy 28–40 bits, fewer than 5 checks passed |
| 3 | Strong | Entropy 40–60 bits, fewer than 7 checks passed |
| 4 | Very Strong | Entropy ≥ 60 bits, all 8 checks passed |

**Entropy formula:** `length × log₂(pool_size)`

Where `pool_size` is the number of distinct character types used:
- Lowercase only: 26
- + Uppercase: +26
- + Digits: +10
- + Symbols: +32

## 🛡️ Security Notes

- All computation happens in the browser — no network requests are made
- The session history uses a simple non-cryptographic hash (FNV-style) for reuse detection only
- "Crack time" estimates assume an offline brute-force attack at 10B guesses/second — real-world times vary widely by attack method
- This tool is for educational purposes and everyday awareness — not a substitute for a professional security audit

## 🙏 Credits

- Icons by [Tabler Icons](https://tabler.io/icons)
- Built with vanilla HTML, CSS, and JavaScript

## 📄 License

[MIT](LICENSE)

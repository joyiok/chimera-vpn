# Design

Late-night operator desk. Copper on charcoal—not GitHub blue, not Material teal.

## Color

Strategy: committed. Accent used only for the connect control and live state.

| Token | OKLCH | Role |
| --- | --- | --- |
| `--bg` | `oklch(0.17 0.018 55)` | App chrome |
| `--surface` | `oklch(0.22 0.02 55)` | Panels |
| `--ink` | `oklch(0.93 0.015 70)` | Body text |
| `--muted` | `oklch(0.74 0.025 60)` | Labels (≥4.5:1 on `--bg`) |
| `--line` | `oklch(0.32 0.02 55)` | Hairline |
| `--accent` | `oklch(0.68 0.14 48)` | Connect, focus |
| `--ok` | `oklch(0.76 0.12 145)` | Connected |
| `--warn` | `oklch(0.78 0.12 85)` | Connecting |
| `--bad` | `oklch(0.68 0.16 25)` | Error |

## Typography

One family: `system-ui`, `"Segoe UI"`, `"Noto Sans SC"`. Traffic uses
`tabular-nums`. Scale 12 / 14 / 16 / 20 / 28. No display fonts.

## Components

- Connect: full-width, 44px min height, copper fill when idle, ink-on-ok when
  connected (label becomes 断开).
- Invite field: monospace, one row, Import + Copy beside it.
- Advanced: native `<details>` / Android expand. Not a modal.
- Radius: 8px controls, 12px panels. No 32px cards.

## Layout

Windows: top status strip, invite, connect, traffic, then advanced / nodes /
logs. Android: same order, single column, 20dp page gutter.

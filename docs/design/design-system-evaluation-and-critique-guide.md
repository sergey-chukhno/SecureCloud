# SecureCloud Desktop Client — UI/UX Design System Specification & Expert Evaluation Package

> **Document Type:** Complete UI/UX Design System Brief, Token Manifest & Expert Critique Guide  
> **Product:** SecureCloud Desktop Messenger (Enterprise-Grade End-to-End Encrypted Client)  
> **Target Audience:** UI/UX Designers, Product Designers, Design Systems Engineers, and AI Design Reviewers  
> **Technology Framework:** Qt 6.6+ / Qt Quick (QML) & C++20 on Desktop (macOS, Windows 11, Linux)  
> **Design Benchmarks:** Linear, Raycast, Signal Desktop, Apple Messages, Telegram Desktop  

---

## Instructions for the Reviewing Designer / AI Assistant

> **Dear Reviewer / Designer:**  
> You are reviewing the complete design system and user experience architecture for **SecureCloud Desktop**, a zero-trust, end-to-end encrypted desktop messaging client built for security-conscious professionals and enterprises.
>
> **Your Mission:**  
> 1. Evaluate our current design tokens, color palettes, typography scale, component ergonomics, and navigation shell.  
> 2. Assess whether our visual identity successfully communicates **cryptographic security, visual calm, modern luxury, and effortless clarity**.  
> 3. Provide constructive, high-impact critiques and actionable enhancements (color token adjustments, micro-interactions, border/depth treatments, typography tuning, and chat ergonomics) to elevate this design system to the level of world-class desktop apps like Linear, Raycast, and macOS native apps.

---

## 1. Product Context, Brand Identity & Aesthetic Tenets

### 1.1 Product Vision
SecureCloud is a desktop messenger where **privacy is non-negotiable**. Every message, media attachment, and cryptographic ratchet is decrypted strictly on the client device using the Signal/Double-Ratchet protocol.

### 1.2 Aesthetic Persona & Brand Adjectives
- **Cryptographic Clarity**: Users must instantly understand security states (verified identity vs unverified contact, active encryption session, emergency status) without deciphering technical jargon.
- **Visual Calm & Minimalist Immersion**: A dark-first interface that fades into the background during extended daily work, avoiding visual fatigue.
- **Enterprise-Grade Precision**: Crisp 1px borders, subtle surface elevations, tactile keyboard accessibility, and zero cartoonish elements.
- **Dual-Theme Parity**: Both Dark and Light themes are first-class citizens with identical contrast fidelity and emotional weight.

### 1.3 Key Architectural Constraints for the Designer
- Built with **Qt Quick (QML)** on desktop: supports hardware-accelerated rendering, smooth property animations, drop shadows, rounded corners, and native OS window framing.
- **No Web Bloat**: Zero webviews (Electron-free). Native performance with instant launch times and low memory consumption ($< 60\text{MB}$).
- **Accessibility Invariant**: Every text element must meet or exceed WCAG 2.1 AA ($\ge 4.5:1$ contrast for body, $\ge 3:1$ for large text and graphical borders).

---

## 2. Complete Color Architecture & Semantic Token Palette

Our theme subsystem (`UiTheme`) supports **Dark Mode**, **Light Mode**, and **System OS Synchronization** (automatically tracking macOS/Windows/Linux appearance switches via `styleHints`).

### 2.1 Complete Semantic Token Manifest

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SURFACE HIERARCHY (3-TIER)                      │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ backgroundPrimary (Canvas / Window Base)                       │   │
│   │ Dark: #0B0F19 | Light: #FFFFFF                                 │   │
│   │                                                                │   │
│   │   ┌────────────────────────────────────────────────────────┐   │   │
│   │   │ backgroundSecondary (Panels, Sidebar, Text Fields)     │   │   │
│   │   │ Dark: #111827 | Light: #F8FAFC                         │   │   │
│   │   │                                                        │   │   │
│   │   │   ┌────────────────────────────────────────────────┐   │   │   │
│   │   │   │ backgroundElevated (Cards, Popovers, Modals)   │   │   │   │
│   │   │   │ Dark: #1F2937 | Light: #FFFFFF                 │   │   │   │
│   │   │   └────────────────────────────────────────────────┘   │   │   │
│   │   └────────────────────────────────────────────────────────┘   │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

| Token Identifier | Dark Mode Hex | Light Mode Hex | Contrast Ratio (vs Base) | Semantic Role & UI Application |
| :--- | :--- | :--- | :--- | :--- |
| `backgroundPrimary` | `#0B0F19` | `#FFFFFF` | Base Canvas | Deep Obsidian base canvas for root window and main backdrop |
| `backgroundSecondary`| `#111827` | `#F8FAFC` | $1.2 : 1$ | Midnight/Slate container for sidebar rail, toolbars, input field boxes |
| `backgroundElevated` | `#1F2937` | `#FFFFFF` | $1.5 : 1$ | Elevated Charcoal card surface, popover menus, floating dialogs |
| `borderSubtle` | `#374151` | `#E2E8F0` | $3.2 : 1$ | 1px boundary lines, card outlines, item divider rules |
| `borderFocused` | `#60A5FA` | `#2563EB` | $4.8 : 1$ | High-visibility focus ring for keyboard navigation & active inputs |
| `textPrimary` | `#F9FAFB` | `#0F172A` | $18.3 : 1$ | Primary titles, chat message content, high-priority labels |
| `textSecondary` | `#9CA3AF` | `#475569` | $5.2 : 1$ | Secondary descriptions, timestamps, subheaders, field labels |
| `textMuted` | `#6B7280` | `#94A3B8` | $3.5 : 1$ | Input placeholders, keyboard shortcut chips, inactive tab text |
| `textInverse` | `#111827` | `#FFFFFF` | $14.1 : 1$ | Text rendered on top of filled primary buttons and badges |
| `accentPrimary` | `#3B82F6` | `#2563EB` | $5.2 : 1$ | Core brand action color, active tab indicators, primary buttons |
| `accentHover` | `#60A5FA` | `#1D4ED8` | — | Hover state feedback on interactive buttons |
| `accentActive` | `#2563EB` | `#1E40AF` | — | Pressed/active state feedback on interactive buttons |
| `statusSuccess` | `#10B981` | `#059669` | $6.4 : 1$ | Verified identity shield ("✓"), online presence dot, session confirmed |
| `statusWarning` | `#F59E0B` | `#D97706` | $5.8 : 1$ | Unverified contact warning ("!"), key rotation alert, reconnecting |
| `statusDanger` | `#EF4444` | `#DC2626` | $5.5 : 1$ | Cryptographic mismatch warning, emergency wipe action, fatal error |
| `statusInfo` | `#06B6D4` | `#0891B2` | $5.9 : 1$ | Protocol version chip, fingerprint info, catalog mode badge |
| `bubbleSelf` | `#1D4ED8` | `#2563EB` | — | Outbound chat bubble background |
| `bubbleSelfText` | `#FFFFFF` | `#FFFFFF` | $8.2 : 1$ | High-contrast text inside outbound chat bubbles |
| `bubblePeer` | `#1F2937` | `#F1F5F9` | — | Inbound peer chat bubble background |
| `bubblePeerText` | `#F9FAFB` | `#0F172A` | $12.4 : 1$ | High-contrast text inside inbound peer chat bubbles |
| `shadowColor` | `rgba(0,0,0,0.4)`| `rgba(0,0,0,0.08)`| — | Drop shadow color for elevated cards and modal backdrops |

---

## 3. Typography Hierarchy & Metrics System

### 3.1 Font Stacks
SecureCloud employs native OS font stacks for optimal text rendering, crisp subpixel anti-aliasing, and zero web-font latency:
- **Primary Font Family (`fontFamilyPrimary`)**:
  - macOS: `-apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', sans-serif`
  - Windows: `'Segoe UI', -apple-system, Roboto, sans-serif`
  - Linux: `Inter, -apple-system, Roboto, 'Noto Sans', Ubuntu, sans-serif`
- **Monospace Font Family (`fontFamilyMonospace`)**:
  - macOS: `'SF Mono', Menlo, Monaco, Consolas, monospace`
  - Windows: `Consolas, 'Courier New', monospace`
  - Linux: `'JetBrains Mono', 'Fira Code', 'DejaVu Sans Mono', monospace`

### 3.2 Monotonic Typography Scale

| Token | Point Size | Pixel Equivalent | Font Weight | Letter Spacing | Typical Application |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `fontDisplay` | $28\text{pt}$ | $\approx 37\text{px}$ | Bold (700) | $-0.02\text{em}$ | Splash welcome headlines, style guide hero titles |
| `fontHeadline`| $24\text{pt}$ | $\approx 32\text{px}$ | Bold (700) | $-0.015\text{em}$| Major view titles (Workspace, Settings, Login) |
| `fontTitle` | $18\text{pt}$ | $\approx 24\text{px}$ | Bold (700) | $-0.01\text{em}$ | Card titles, modal dialog titles |
| `fontSubtitle`| $15\text{pt}$ | $\approx 20\text{px}$ | SemiBold (600)| Normal | Conversation contact headers, section dividers |
| `fontHeader` | $15\text{pt}$ | $\approx 20\text{px}$ | SemiBold (600)| Normal | Semantic alias for `fontSubtitle` |
| `fontBody` | $13\text{pt}$ | $\approx 17\text{px}$ | Regular (400) | Normal | Chat message text, input values, body descriptions |
| `fontCaption` | $11\text{pt}$ | $\approx 15\text{px}$ | Regular (400) | $+0.01\text{em}$ | Timestamps, status badge text, breadcrumbs |
| `fontMicro` | $10\text{pt}$ | $\approx 13\text{px}$ | Regular (400) | $+0.02\text{em}$ | Keyboard shortcut chips (`Ctrl+1`), avatar subscripts |

### 3.3 8-Point Spacing Grid & Radius Metrics

- **Spacing Scale**:
  - `space2` ($2\text{px}$): Micro border offsets
  - `space4` ($4\text{px}$): Label-to-input gap, icon-to-badge margin
  - `space8` ($8\text{px}$): Toolbar gaps, compact button icon padding
  - `space12` ($12\text{px}$): Sidebar item padding, compact list gaps
  - `space16` ($16\text{px}$): Standard container padding, card margin
  - `space24` ($24\text{px}$): Inter-section card margins
  - `space32` ($32\text{px}$): Window gutter padding, page margins
- **Corner Radii Scale**:
  - `radiusSmall` ($6\text{px}$): Inputs, icon buttons, tooltips
  - `radiusMedium` ($10\text{px}$): Action buttons, standard cards, dropdowns
  - `radiusLarge` ($16\text{px}$): Modal dialogs, elevated panels
  - `radiusRound` ($9999\text{px}$): Avatars, status dots, pills
- **Motion Durations**:
  - `durationFast` ($150\text{ms}$, `Easing.OutQuad`): Button hover/pressed, focus rings
  - `durationNormal` ($250\text{ms}$, `Easing.OutQuad`): Sidebar collapse/expand, modal fade
  - `durationSlow` ($400\text{ms}$, `Easing.OutCubic`): Full view crossfades

---

## 4. Component Library Architecture & Anatomy

### 4.1 `SCButton` — Action Button
- **Variants**:
  - `Primary`: Solid `#3B82F6` (Dark) / `#2563EB` (Light) with high-contrast text.
  - `Secondary`: Outlined button with `#111827` background and `#374151` border.
  - `Ghost`: Borderless transparent background, subtle hover highlight.
  - `Danger`: High-visibility red button (`#EF4444`) reserved for destructive actions.
- **Interactive States**: Default $\to$ Hover $\to$ Pressed $\to$ Focused (outer 2px focus ring `#60A5FA` with 2px gap) $\to$ Disabled (40% opacity).
- **Busy State**: Disables user interaction and renders a smooth animated rotating circular spinner.

### 4.2 `SCTextField` — Form & Credential Input
- **Anatomy**: Top label (bold caption), input box container, text area, right accessory slot (reveal eye or clear button), and bottom validation error message.
- **Security Features**:
  - Masked password mode with toggleable eye icon (`👁` / `🔒`).
  - Monospace font mode for cryptographic fingerprints, public keys, and safety numbers.
  - Validation error state: border turns `#EF4444`, input glow turns red, and an explanatory error string renders below in red text.

### 4.3 `SCIconButton` — Compact Header Action
- Square dimensions ($34 \times 34\text{px}$ default), rounded corners ($6\text{px}$).
- Native tooltip support on hover.
- Notification badge pill in top-right corner with automatic high-contrast background and white counter text.

### 4.4 `SCCard` — Structural Framing Container
- Dual elevation modes: `Base` (standard flat container with subtle border) vs `Elevated` (floating container with drop shadow).
- Header slot: optional icon + bold title separated from the content body by a subtle 1px divider rule.

### 4.5 `SCBadge` — Cryptographic Verification & Presence Pill
- Pill-shaped container (`radiusRound`) with 6 semantic modes:
  - `Verified`: Green border and text, shield icon `"✓"`.
  - `Unverified`: Amber warning border and text, alert icon `"!"`.
  - `Online` / `Offline`: Colored circular dot indicator.
  - `Danger`: Bright red alert badge.
  - `Info`: Cyan metadata chip.
- *Accessibility design*: Always pairs icon/shape with text so color-blind users can instantly distinguish status.

### 4.6 `SCAvatar` — Deterministic Cryptographic Identity
- Circular avatar displaying two initials.
- **Deterministic Color Derivation**: Computes a polynomial rolling hash from `userId` modulo 8, mapping to 8 distinct, accessible brand tones (`#3B82F6`, `#10B981`, `#8B5CF6`, `#F59E0B`, `#EC4899`, `#06B6D4`, `#14B8A6`, `#6366F1`). Every user has an identical, recognizable color across all devices without contacting an avatar server.
- Optional presence dot (Online = green, Busy = amber, Offline = gray) positioned at the bottom-right corner.

### 4.7 `SCDialog` — Modal Shield & Confirmation
- Full-window dimming backdrop (`rgba(0, 0, 0, 0.6)`) that captures and shields all underlying mouse events.
- Elevated card container with title, explanatory text, confirm button, and cancel button.
- `isDanger: true` renders the confirm button in red Danger variant for high-risk operations (e.g. cryptographic emergency wipe).
- Supports keyboard dismissal via `Esc`.

---

## 5. Desktop Window Shell & Navigation Architecture

### 5.1 Responsive Constraints & Window Management (`WindowStateManager`)
- **Default Launch Size**: $1200 \times 800\text{px}$ (optimal for multi-column chat feeds).
- **Minimum Clamped Size**: $960 \times 640\text{px}$ (strictly enforced; window cannot be resized smaller, guaranteeing security badges and safety numbers are never occluded).
- **Multi-Monitor Bounds Sanitization**: Inspects `QGuiApplication::screens()`. If the user disconnects a monitor, the window automatically clamps and centers onto the primary active screen with at least $120\text{px}$ visibility.
- **State Persistence**: Debounced JSON persistence saving window coordinates, dimensions, and maximized state to `$APP_DATA/window_state.json`.

### 5.2 Desktop Layout Anatomy (`NavigationShell.qml`)

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ TOP HEADER TOOLBAR: App Title | Verified Badge | User Avatar Chip | Theme Toggle | Quick Actions │
├──────────────┬───────────────────────────────────────────────────────────────────────────────────┤
│ SIDEBAR RAIL │ CONTEXT BREADCRUMB BAR: SecureCloud › Workspace                [Catalog Mode Badge]│
│ (200px /     ├───────────────────────────────────────────────────────────────────────────────────┤
│  64px        │ NOTIFICATION / ROUTE DENIED ALERT BANNER (Animated height, red background)        │
│  collapsed)  ├───────────────────────────────────────────────────────────────────────────────────┤
│              │                                                                                   │
│ [☰] Toggle   │                                                                                   │
│              │                                                                                   │
│ 💬 Workspace │                               PRIMARY CONTENT AREA                                │
│    [Ctrl+1]  │                            (Active View via Loader)                               │
│              │                                                                                   │
│ ⚙️ Settings  │                                                                                   │
│    [Ctrl+2]  │                                                                                   │
│              │                                                                                   │
│ 🎨 StyleGuide│                                                                                   │
│    [Ctrl+3]  │                                                                                   │
│              │                                                                                   │
│              │                                                                                   │
│ 🚨 Emergency │                                                                                   │
│    [Ctrl+Sh+E│                                                                                   │
├──────────────┴───────────────────────────────────────────────────────────────────────────────────┤
│ BOTTOM STATUS BAR: Connection State (Connected/Disconnected) | Active View | E2EE Shield Badge   │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **Collapsible Rail**: $200\text{px}$ expanded $\to$ $64\text{px}$ collapsed with smooth easing animation. Auto-collapses when window width $< 1000\text{px}$.
- **Global Keyboard Shortcuts**: `Ctrl+1` (Workspace), `Ctrl+2` (Settings), `Ctrl+3` (Style Guide Gallery), `Ctrl+Shift+E` (Emergency Wipe modal), `Alt+Left` / `Esc` (Back navigation).
- **Route Guards**: Authoritative C++ `NavigationController` blocks unauthenticated navigation attempts to restricted routes and displays a high-contrast denial banner.

---

## 6. Designer Evaluation Questionnaire & Review Prompts

Please review the design system above and provide feedback across the following 6 core design dimensions:

### 1. Palette & Emotional Resonance
- Does the 3-tier dark surface hierarchy (`#0B0F19` canvas, `#111827` panels, `#1F2937` cards) evoke cryptographic security and visual luxury, or does it feel too cold/sterile?
- Should we introduce subtle blue/slate undertones into the surfaces, or explore subtle glassmorphic translucency/vibrancy (e.g. macOS acrylic/blur effects) for sidebars?
- In Light Mode, does the palette (`#FFFFFF` canvas, `#F8FAFC` panels) provide sufficient visual depth without looking flat?

### 2. Micro-Interactions, Shadows & Depth
- Currently, elevation uses subtle 1px borders (`#374151`) and clean drop shadows (`rgba(0, 0, 0, 0.4)`). Would you recommend multi-layered ambient shadows or subtle 1px inner highlights (hairline borders) to give cards a more tactile feel?
- How can we make the active focus ring (`#60A5FA`) feel more refined (e.g., dual-ring outline with 2px offset)?

### 3. Typography Rhythm & Hierarchy
- Is the monotonic scale (Display 28pt, Headline 24pt, Title 18pt, Subtitle 15pt, Body 13pt, Caption 11pt, Micro 10pt) well-balanced for dense chat interfaces?
- For message copy ($13\text{pt}$ / $\approx 17\text{px}$), is the line height and weight optimal for prolonged reading?

### 4. Chat Message Ergonomics (Upcoming Features)
- In our upcoming messaging view, we plan to use `#1D4ED8` (self bubbles) and `#1F2937` (peer bubbles). How would you approach bubble corner radii (e.g. asymmetrical grouping corners for consecutive messages)?
- How should safety number verification badges be integrated into message headers without cluttering the conversation flow?

### 5. Layout Density & Information Architecture
- The navigation rail currently offers an expanded mode ($200\text{px}$) and a collapsed mode ($64\text{px}$). Do these proportions feel balanced alongside a conversation list ($280\text{px}$) and message thread ($> 600\text{px}$)?
- Should we provide user-selectable density presets (e.g. *Compact* for power users vs *Comfortable* for casual use)?

### 6. Specific Component Suggestions
- What specific visual or behavioral improvements would you recommend for `SCButton`, `SCTextField`, `SCBadge`, `SCAvatar`, or `SCDialog`?

---

*Thank you for evaluating the SecureCloud Client Design System. Your suggestions will directly inform our upcoming client feature cards (CLIENT-003 through CLIENT-016)!*

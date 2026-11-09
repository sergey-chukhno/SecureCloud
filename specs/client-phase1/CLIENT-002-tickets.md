# CLIENT-002 — Client UI Design System & Navigation
## Client Phase 1 (UI & Endpoint Foundation) Technical Specification & Implementation Tickets

**Card Identifier**: CLIENT-002  
**Milestone**: Client Phase 1 — Desktop Client Foundation & Core User Interface  
**Document Status**: Implementation-Ready Technical Specification  
**Assignee / Developer**: Lorenzo  
**Reviewer & Gatekeeper**: Sergey (Technical Lead & Security Architect)  
**Date**: November 3, 2026  

---

## 1. Executive Summary & Architectural Scope

Card **CLIENT-002** establishes the desktop application's **Visual Design System, Reusable QML Components, Responsive Window Shell, and View Routing Integration** for the **SecureCloud Desktop Client** (`securecloud-client`) using **C++20**, **Qt 6 / Qt Quick (QML)**, and **CMake**.

Following the successful completion of the application foundation in **CLIENT-001**, `CLIENT-002` bridges the gap between C++ domain orchestration and user-facing presentation. It establishes a consistent, dark-themed, security-focused visual hierarchy that will serve as the unified design language for all subsequent feature cards (Authentication in `CLIENT-003`, Messaging in `CLIENT-004`, File Transfer in `CLIENT-013`, and Emergency Actions in `CLIENT-014`).

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        SecureCloud Desktop Client                      │
│                                                                        │
│  Presentation Shell (QML / Qt Quick)                                   │
│  ├── Design System Tokens (Theme.qml: Colors, Typography, Metrics)    │
│  ├── Reusable Controls (SCButton, SCTextField, SCCard, SCAvatar, etc.)│
│  └── Navigation Shell (Header, Breadcrumb, Dynamic View Loader)        │
│         │                                                              │
│         ▼                                                              │
│  C++ Presentation Coordinators (securecloud_client_ui)                 │
│  ├── NavigationController (Deterministic Route State Machine)          │
│  ├── AppViewModel (Observable Presentation State)                      │
│  └── WindowStateManager (Window Geometry & Position Persistence)       │
│         │                                                              │
│         ▼                                                              │
│  C++ Application Engine (securecloud_client_app: ClientBootstrap)      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Architectural Invariants & Non-Negotiable Boundaries

1. **Strictly Zero Business Logic in QML (`client-architecture-and-foundation.md` §1.3)**:
   - QML components must be strictly declarative presentation views.
   - All state transitions, authorization guards, routing decisions, validation algorithms, and data formatting must occur in C++ (`NavigationController`, ViewModels).
   - QML components must never import `QtQuick.LocalStorage`, perform network requests, or manage cryptographic key state.
2. **Immutable Design Tokens & Centralized Theming**:
   - Visual attributes (colors, typography, spacing, border radii, animation durations) must be defined centrally in a single design system module (`Theme.qml` or a C++ theme provider registered as a singleton instance).
   - Arbitrary hardcoded hexadecimal color codes or raw pixel sizes scattered throughout views are strictly prohibited.
   - High-contrast visual indicators for cryptographic security states: green for verified/trusted, amber for unverified/unknown, red for revoked/compromised/danger.
3. **Responsive Window Geometry & State Persistence**:
   - The desktop client window must adapt fluidly to screen resolutions (minimum resolution: 960×640, recommended default: 1280×800).
   - Window size, position, and maximized state must be persisted between launches via a dedicated, sanitized C++ service (`WindowStateManager`) without leaking sensitive user context.
4. **Deterministic Route Guards & Keyboard Navigation**:
   - Navigation transitions must be driven exclusively through `NavigationController`.
   - Accessible keyboard navigation must be supported across all primary controls (`Tab` focus ordering, `Return` activation, `Esc` back-traversal, `Ctrl+1..4` view switching).
5. **Headless Verification & Testability**:
   - All QML components, style tokens, and layout sizing rules must be verifiable in automated test suites without requiring a physical monitor or GPU, using `QT_QPA_PLATFORM=offscreen` and `QtTest` / GTest.

---

## 3. Dependency Graph

```text
                       CLIENT-001
        (Client Application Foundation & Target Topologies)
                           │
                           ▼
                     CLIENT-002-T01
       (Design Tokens, Palette Engine & Theming Subsystem)
                           │
                           ▼
                     CLIENT-002-T02
       (Atomic Form & Interactive Controls: SCButton, SCTextField)
                           │
                           ▼
                     CLIENT-002-T03
       (Structural & Identity Primitives: SCCard, SCBadge, SCAvatar)
                           │
                           ▼
                     CLIENT-002-T04
       (Responsive Window Geometry & State Persistence Engine)
                           │
                           ▼
                     CLIENT-002-T05
       (Refined Navigation Shell, View Routing & Keyboard Accessibility)
                           │
                           ▼
                     CLIENT-002-T06
       (Component Verification Test Suite & Design System Specification)
```

---

## 4. Implementation Tickets for Developer Lorenzo

### CLIENT-002-T01 — Design Tokens, Palette Engine & Theming Subsystem

1. **Ticket ID**: `CLIENT-002-T01`
2. **Title**: Design Tokens, Palette Engine & Theming Subsystem
3. **Objective**: Implement the centralized design token system (`Theme.qml` and C++ theme bridge), establishing standard color palettes, typography scales, spacing metrics, and elevation/shadow definitions.
4. **Architectural Purpose**: Eliminates visual drift and magic values across QML views, ensuring consistent security-focused visual cues throughout the application.
5. **Scope & Files to Change**:
   - `src/client/ui/qml/Theme.qml`:
     - **Color Palette (Dark Theme Baseline)**:
       - Backgrounds: `backgroundPrimary` (`#0F141C`), `backgroundSecondary` (`#18202C`), `backgroundElevated` (`#222D3D`).
       - Borders: `borderSubtle` (`#2E3C52`), `borderFocused` (`#3B82F6`).
       - Text: `textPrimary` (`#F8FAFC`), `textSecondary` (`#94A3B8`), `textMuted` (`#64748B`), `textInverse` (`#0F172A`).
       - Accents: `accentPrimary` (`#2563EB`), `accentHover` (`#1D4ED8`), `accentActive` (`#1E40AF`).
       - Security & Status: `statusSuccess` (`#10B981` / verified), `statusWarning` (`#F59E0B` / unverified), `statusDanger` (`#EF4444` / revoked/panic), `statusInfo` (`#3B82F6`).
     - **Typography Metrics**:
       - Font families: Primary UI (`system-ui`, `-apple-system`, `Segoe UI`, `Roboto`), Monospace for fingerprints and hashes (`SF Mono`, `Cascadia Code`, `Consolas`, `monospace`).
       - Font sizes: `fontCaption` (11pt), `fontBody` (13pt), `fontSubtitle` (15pt), `fontTitle` (18pt), `fontHeadline` (24pt).
       - Font weights: `weightNormal` (400), `weightMedium` (500), `weightBold` (700).
     - **Spacing & Layout Metrics**:
       - Spacing scale: `space2` (2px), `space4` (4px), `space8` (8px), `space12` (12px), `space16` (16px), `space24` (24px), `space32` (32px).
       - Radius scale: `radiusSmall` (4px), `radiusMedium` (8px), `radiusLarge` (12px), `radiusRound` (9999px).
       - Durations: `durationFast` (150ms), `durationNormal` (250ms), `durationSlow` (400ms).
   - `src/client/ui/qml.qrc`: Register `Theme.qml`.
   - `src/client/ui/theme_bridge.{hpp,cpp}`: Optional C++ helper exposing OS theme synchronization (detecting dark mode preference via `QGuiApplication::styleHints()`).
6. **Dependencies**: `CLIENT-001`.
7. **Implementation Approach**:
   - Register `Theme.qml` as a QML singleton (`pragma Singleton`) accessible anywhere as `Theme.backgroundPrimary`, `Theme.fontBody`, etc.
8. **Tests & Validation**:
   - Verify QML engine loads `Theme.qml` without syntax or scoping errors.
   - Assert all color strings adhere to valid hex notation and typography metrics are positive integers.
9. **Acceptance Criteria**:
   - `Theme` is globally accessible in QML as a singleton.
   - All color, typography, spacing, and radius tokens match specification.
   - Zero hardcoded magic color values required in downstream components.

---

### CLIENT-002-T02 — Atomic Form & Interactive Controls

1. **Ticket ID**: `CLIENT-002-T02`
2. **Title**: Atomic Form & Interactive Controls (`SCButton`, `SCTextField`, `SCIconButton`)
3. **Objective**: Implement reusable atomic form controls adhering strictly to `Theme.qml` tokens with full support for hover, pressed, focused, disabled, and keyboard navigation states.
4. **Architectural Purpose**: Guarantees accessible, consistent, and secure user inputs, ensuring passwords and sensitive credentials are handled safely without unintended clipboard or diagnostic leaks.
5. **Scope & Files to Change**:
   - `src/client/ui/qml/controls/SCButton.qml`:
     - Variants: `Primary`, `Secondary`, `Ghost`, `Danger` (for emergency/wipe triggers).
     - States: Default, Hovered, Pressed, Focused (with visible high-contrast focus ring), Disabled.
     - Properties: `text`, `iconSource`, `variant`, `enabled`, `busy` (loading spinner).
   - `src/client/ui/qml/controls/SCTextField.qml`:
     - States: Normal, Focused, Invalid/Error (with error text label), Disabled.
     - Security Features: `isPassword` flag with optional reveal toggle, clear button, monospace font support for safety numbers/keys.
     - Signal: `accepted()`, `textModified()`.
   - `src/client/ui/qml/controls/SCIconButton.qml`:
     - Compact action button with tooltip support and accessibility descriptions.
   - `src/client/ui/qml.qrc`: Register new controls under `qrc:/qml/controls/`.
6. **Dependencies**: `CLIENT-002-T01`.
7. **Implementation Approach**:
   - Implement controls using pure Qt Quick primitives (`Item`, `Rectangle`, `Text`, `MouseArea`, `TextInput`) with hardware-accelerated transitions.
   - Expose standard `Accessible.name` and `Accessible.role` for accessibility compliance.
8. **Tests & Validation**:
   - Headless QML tests verifying button click emission, disabled state suppression, password masking, and error border styling.
9. **Acceptance Criteria**:
   - `SCButton` renders all 4 variants with correct color tokens and responsive hover/pressed animations.
   - `SCTextField` supports password masking, error message display, and tab focus traversal.
   - All controls adhere 100% to `Theme.qml` tokens.

---

### CLIENT-002-T03 — Structural & Identity Presentation Primitives

1. **Ticket ID**: `CLIENT-002-T03`
2. **Title**: Structural & Identity Primitives (`SCCard`, `SCBadge`, `SCAvatar`, `SCDialog`)
3. **Objective**: Implement structural containers, status indicators, user identity presentation avatars, and modal confirmation dialogs.
4. **Architectural Purpose**: Provides reusable visual framing for messaging bubbles, contact lists, verification safety numbers, and high-risk action confirmation modals (e.g., emergency wipe confirmation).
5. **Scope & Files to Change**:
   - `src/client/ui/qml/controls/SCCard.qml`:
     - Elevated background container with customizable padding, border, and optional header/footer slots.
   - `src/client/ui/qml/controls/SCBadge.qml`:
     - Status badges: `Online`, `Offline`, `Verified` (green shield), `Unverified` (amber shield), `Direct`, `Group`.
   - `src/client/ui/qml/controls/SCAvatar.qml`:
     - Circular avatar rendering: Displays user image URL if available; falls back cleanly to deterministic initials and background hash color based on `UserId`.
     - Presence indicator dot (online/offline/busy).
   - `src/client/ui/qml/controls/SCDialog.qml`:
     - Modal overlay with backdrop dimming, title, message text, confirm button, and cancel button.
     - Special `Danger` mode requiring explicit confirmation text input for destructive operations.
   - `src/client/ui/qml.qrc`: Register new primitives under `qrc:/qml/controls/`.
6. **Dependencies**: `CLIENT-002-T01`, `CLIENT-002-T02`.
7. **Implementation Approach**:
   - Declarative composition leveraging Qt Quick layout primitives (`ColumnLayout`, `RowLayout`).
   - Use `ClipPath` or `Rectangle.radius` for rounded avatar rendering without external image processing libraries.
8. **Tests & Validation**:
   - Unit tests verifying initials generation for various name formats (e.g., "Alice Smith" $\to$ "AS", "bob" $\to$ "B").
   - Test `SCDialog` confirm/cancel signal emission and modality capture.
9. **Acceptance Criteria**:
   - `SCAvatar` computes deterministic fallback initials and colors for any `UserId`.
   - `SCBadge` visually represents verification states accurately.
   - `SCDialog` blocks underlying mouse events while open and emits clean signals.

---

### CLIENT-002-T04 — Responsive Window Shell, Geometry & State Persistence

1. **Ticket ID**: `CLIENT-002-T04`
2. **Title**: Responsive Window Shell, Geometry & State Persistence
3. **Objective**: Implement the `WindowStateManager` C++ service to manage window size, positioning, responsive layout breakpoints, and persistent geometry restoration across application restarts.
4. **Architectural Purpose**: Prevents erratic window positioning on multi-monitor setups and enforces minimum display constraints so critical security UI (e.g., safety numbers or emergency confirmation) is never cropped or occluded.
5. **Scope & Files to Change**:
   - `src/client/ui/window_state_manager.hpp` & `.cpp`:
     - Manages properties: `windowWidth`, `windowHeight`, `windowX`, `windowY`, `isMaximized`.
     - Methods: `load_geometry()`, `save_geometry(width, height, x, y, is_maximized)`.
     - Validates geometry against available screen geometry (`QGuiApplication::screens()`) to prevent offscreen coordinates.
     - Enforces minimum width (960px) and minimum height (640px).
   - `src/client/ui/CMakeLists.txt`: Add `window_state_manager.{hpp,cpp}` to `securecloud_client_ui`.
   - `src/client/main.cpp`: Instantiate `WindowStateManager` and register as context property `windowStateManager`.
   - `src/client/ui/qml/Main.qml`: Bind `ApplicationWindow` geometry to `windowStateManager` and save state on window move/resize/quit.
6. **Dependencies**: `CLIENT-001`, `CLIENT-002-T01`.
7. **Implementation Approach**:
   - Save window geometry to a dedicated local configuration file (`$APP_DATA/window_state.json`) or via `ClientConfig`.
   - Debounce geometry save requests (e.g., 500ms debounce timer) to avoid disk thrashing during active window resizing.
8. **Tests & Validation**:
   - `WindowStateManagerTest`: Test geometry validation, offscreen coordinate correction, minimum size clamping, and persistence round-trip.
9. **Acceptance Criteria**:
   - Minimum window dimensions strictly enforced (960×640).
   - Window position and size restore accurately upon application restart.
   - Offscreen or disconnected monitor coordinates automatically clamp back to the primary display.

---

### CLIENT-002-T05 — Unified Navigation Shell, View Routing & Keyboard Accessibility

1. **Ticket ID**: `CLIENT-002-T05`
2. **Title**: Unified Navigation Shell, View Routing & Keyboard Accessibility
3. **Objective**: Refine `NavigationShell.qml` with a modern top bar, breadcrumb navigation, view switching controls, responsive sidebar toggle, and global keyboard navigation shortcuts.
4. **Architectural Purpose**: Connects the atomic controls and theming system directly to the C++ `NavigationController`, providing a complete desktop shell ready to host feature modules.
5. **Scope & Files to Change**:
   - `src/client/ui/qml/NavigationShell.qml`:
     - Top Header Bar: Application logo/brand, active view title, breadcrumb trail, user profile/avatar chip, emergency wipe icon button.
     - Main Body Layout: Split view containing navigation rail/sidebar (collapsible) and primary content `Loader`.
     - Status Bar: Connection indicator (`Connected` green / `Disconnected` amber), sync status, active device fingerprint preview.
   - Keyboard Shortcuts & Actions:
     - `Ctrl+1`: Navigate to Workspace (`MainWorkspaceView`).
     - `Ctrl+2`: Navigate to Settings (`SettingsView`).
     - `Ctrl+Shift+E`: Trigger Emergency confirmation dialog (`EmergencyView`).
     - `Alt+Left` / `Esc`: Go back (`navController.goBack()`).
   - Placeholder View Upgrades:
     - Update `LoginPlaceholder.qml`, `WorkspacePlaceholder.qml`, `SettingsPlaceholder.qml`, and `EmergencyPlaceholder.qml` to utilize `Theme`, `SCButton`, `SCTextField`, and `SCCard`.
6. **Dependencies**: `CLIENT-002-T01` through `CLIENT-002-T04`.
7. **Implementation Approach**:
   - All navigation triggers delegate strictly to `navController.navigateTo()` and `navController.goBack()`.
   - Route guards in `NavigationController` remain authoritative; the UI shell reflects denied navigation via status alerts.
8. **Tests & Validation**:
   - Headless verification of keyboard shortcut activations and loader source resolution.
   - Verification that restricted views remain blocked when unauthenticated.
9. **Acceptance Criteria**:
   - `NavigationShell.qml` provides a cohesive desktop layout adhering to `Theme.qml`.
   - Breadcrumb trail updates dynamically with `navController.currentView`.
   - Global keyboard shortcuts trigger corresponding navigation methods.
   - Status bar reflects live `AppViewModel` connection and session state.

---

### CLIENT-002-T06 — Component Verification Test Suite & Design System Specification

1. **Ticket ID**: `CLIENT-002-T06`
2. **Title**: Component Verification Test Suite & Design System Specification
3. **Objective**: Create automated unit tests for QML controls and `WindowStateManager`, verify headless offscreen execution, format all codebase files, and author the design system specification document.
4. **Architectural Purpose**: Guarantees zero regressions, 100% CI reproducibility without physical displays, and provides a clear style guide for engineers implementing subsequent cards (`CLIENT-003` through `CLIENT-016`).
5. **Scope & Files to Change**:
   - `tests/unit/client/window_state_manager_test.cpp`: Unit tests for window geometry calculations and boundaries.
   - `tests/unit/client/ui_components_test.cpp`: Automated Qt Quick headless component instantiation and signal testing.
   - `tests/unit/CMakeLists.txt`: Register UI component test targets.
   - `docs/architecture/client-ui-design-system.md`: Comprehensive design system reference documenting token palettes, typography rules, component usage snippets, and accessibility standards.
6. **Dependencies**: `CLIENT-002-T01` through `CLIENT-002-T05`.
7. **Implementation Approach**:
   - Use `QQuickView` / `QQmlComponent` in offscreen mode (`QT_QPA_PLATFORM=offscreen`) to programmatically instantiate components and assert property bindings.
8. **Tests & Validation Commands**:
   - `cmake --build build/dev-debug --target check-format`: 100% `.clang-format` compliance.
   - `ctest --test-dir build/dev-debug -R "client" --output-on-failure`: All client tests pass.
   - `./build/dev-debug/src/client/securecloud-client --smoke-test`: Clean headless startup and teardown.
9. **Acceptance Criteria**:
   - 100% test pass rate across all new UI component and window state tests.
   - Design system specification document complete and reviewed.
   - All C++ files compile with zero warnings under `-Wall -Wextra -Werror -Wpedantic`.

---

## 5. Traceability Matrix to Acceptance Criteria

| Acceptance Criterion | Ticket(s) | Verification Method |
| :--- | :--- | :--- |
| **Shared design tokens, typography, spacing, colors** | `T01` | `Theme.qml` singleton properties & test validation |
| **Reusable QML components (`SCButton`, `SCTextField`, `SCCard`, etc.)** | `T02`, `T03` | Offscreen component instantiation tests in `ui_components_test.cpp` |
| **Deterministic navigation managed by C++** | `T05` | `NavigationControllerTest` & route guard verification |
| **Authentication-aware route guards** | `T05` | Unauthenticated transition tests in `NavigationController` |
| **Clear navigation: Login, Workspace, Settings, Emergency** | `T05` | `NavigationShell` loader source assertions |
| **Zero business logic in QML** | `T01`–`T05` | Code review and architectural boundary enforcement |
| **UI state exposed through ViewModels and C++ interfaces** | `T04`, `T05` | `AppViewModel` and `WindowStateManager` property bindings |
| **Window geometry & state persistence** | `T04` | `WindowStateManagerTest` round-trip persistence tests |
| **Design system architectural documentation** | `T06` | `docs/architecture/client-ui-design-system.md` |

---

## 6. Implementation Gate & Next Steps

> [!IMPORTANT]
> In accordance with project instructions, all code modifications remain paused until the Technical Lead and Security Architect explicitly review and approve this specification.
> 
> Once approved:
> 1. Implementation will proceed on feature branch `feature/client-002-client-ui-design-system-and-navigation`.
> 2. Tickets will be executed in topological order: `T01` $\to$ `T02` $\to$ `T03` $\to$ `T04` $\to$ `T05` $\to$ `T06`.
> 3. Each ticket will maintain zero compiler warnings (`-Wall -Wextra -Werror -Wpedantic`), 100% `.clang-format` conformance, and offscreen headless test verification.


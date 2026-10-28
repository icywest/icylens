# Frontend Traditional UI Design

## Correction scope

FE-04.1 replaces the FE-04 visual direction without changing its behavior. The previous interface was functionally complete but used a near-black canvas, oversized editorial headline, numbered panels, decorative icon containers, uppercase metadata, and a complex asymmetric grid. Those choices made the academic file utility resemble a generic modern dashboard or marketing page.

The corrected interface is a conventional light-first software tool. It prioritizes the file form, readable properties, restrained technical visualizations, and familiar section hierarchy.

## Branding and palette

iCYLENS remains independent and is labeled **File Analysis Lab**. No ESET logo, slogan, certification, or affiliation is presented. The documented ESET Mid Turquoise `#0096a1` is used only as a color reference for the brand name, focus treatment, meter fills, active accents, and small indicators.

Core tokens:

| Purpose | Value |
|---|---|
| Primary reference | `#0096a1` |
| Primary hover/link | `#007f89` |
| Primary subtle | `#e8f5f5` |
| Background | `#f7f8f9` |
| Surface | `#ffffff` |
| Text | `#263238` |
| Secondary text | `#687780` |
| Border | `#dee4e7` |

Small white text on `#0096a1` does not provide sufficient contrast for every use. Primary action buttons therefore use the documented darker `#007f89` token with white text, while `#0096a1` remains the visible brand and focus accent.

## Typography and layout

The interface uses the system sans-serif stack and conventional sizes: approximately 27–30 px for the page title, 17 px for section headings, 14–15 px body copy, and 12–13 px metadata. Monospace is reserved for hashes and analysis identifiers.

The main content width is 1200 px. The page contains a plain header, short page heading, upload form, results, and footer. Results are a single conventional stack rather than a 12-column dashboard. Columns remain only inside static analysis where entropy and related observations benefit from side-by-side reading.

## Header

The header contains only the iCYLENS name, File Analysis Lab descriptor, and real backend connectivity text. The former monogram container and bordered status badge were removed. Connectivity still begins as neutral “Checking API” and changes only after the actual health response.

## Upload form

The initial state is a compact file form with **Select a file**, **Choose file**, and `Single file · Maximum 10 MiB`. The full row remains a drag-and-drop and keyboard target, but drag-and-drop no longer dominates the composition.

Selected, analyzing, completed, retry, removal, and replacement behavior remains unchanged. Error messages use a narrow left border and subtle background instead of a large alert panel.

## Results

File information is presented as a property table containing filename, size, detected format, MIME, extension, consistency, validation status, analysis type, and copyable SHA-256.

Static analysis retains the exact entropy value and 0–8 bits/byte scale, string counts, configured retention capacity, indicators, and truncation status. Counts are visually modest and no longer resemble dashboard KPIs.

The analysis process is a conventional expandable list with an explicit conceptual-model notice. Scientific limitations are rendered as a readable bullet list. The synthetic ML educational lab uses a muted secondary section and warm provenance notice, remaining clearly separate from the file analysis.

## Responsive behavior

The property table uses aligned label/value columns on desktop and tablet. At narrow mobile widths each row stacks its label above the value, hashes wrap, controls stack, and static analysis becomes one column. Browser validation found no horizontal overflow at 1920, 1440, 768, 390, or 375 px, including a deliberately extreme filename.

## Accessibility

The redesign preserves the skip link, semantic landmarks and headings, keyboard file selection, drag-and-drop, native buttons, visible focus rings, live status announcements, accessible meters, textual chart equivalents, color-independent connectivity text, touch targets, and reduced motion. A browser configured for reduced motion reduced the processing animation to `0.00001s`.

## Visual comparison

Compared with FE-04, FE-04.1 removes:

- the dark futuristic canvas;
- giant hero typography;
- numbered and asymmetric dashboard cards;
- repetitive icon boxes and pill-like status styling;
- extensive uppercase micro-labels;
- large metric presentation and decorative hierarchy.

It replaces them with a familiar white header, moderate page title, compact upload form, property table, bordered software sections, standard typography, small teal accents, and conventional spacing. Real Microsoft Edge screenshots of empty, selected, analyzing, completed, error, desktop, tablet, and mobile states were inspected—not inferred from the build.

## Boundaries

No backend route, HTTP contract, analytical feature, model, persistence mechanism, external service, or third-party UI library was added. The design uses the existing Astro, React, Tailwind processing, and Lucide dependency set.

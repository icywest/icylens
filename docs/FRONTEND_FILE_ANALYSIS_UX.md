# FRONTEND FILE ANALYSIS UX (FE-01)

## States
1. Initial - Branding (iCYLENS / File Analysis Lab), description, FileUploader, academic disclaimer
2. File Selected - Show filename/size/type, Analyze button, Remove option
3. Analyzing - Loading/processing state with brief technical message (no fabricated percentages)
4. Completed - Results section with prepared structure (File overview, Hashes, Technical properties, Analysis sections, Limitations/Explanations)
5. Error - Clear, safe message (no stack traces)

## Interactions
- Drag and drop or file picker (single file)
- File replacement/removal
- Keyboard accessible (tabindex, Enter/Space on dropzone)
- Focus states visible
- Size validation (client-side) - matches backend limit of 10 MiB

## Principles
- Minimal, dark, technical, academic
- Single accent-free neutral palette
- Subtle borders
- Clear hierarchy
- No cyberpunk/neon, no dashboards/gauges, no fake metrics
- No persistence/history

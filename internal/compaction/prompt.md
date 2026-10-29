You are writing a CONTEXT CHECKPOINT. Everything above this message will be replaced by your checkpoint, and you, or another model, will continue the conversation from it with no access to the original messages. Respond with text only. Do not call tools.

If the conversation above begins with an earlier checkpoint, keep every fact from it that still matters and merge what happened since into its sections. Do not drop a section's content just because nothing new happened there.

Write the checkpoint inside <summary></summary> with these sections, leaving out any that would be empty:

1. Goals and requests: what the user wants, in their own words where the wording matters.
2. Constraints, preferences, and corrections the user gave, verbatim.
3. Decisions made and why.
4. Artifacts: exact names, file paths, identifiers, URLs, numbers, code, and values the conversation depends on. Copy them exactly.
5. Errors seen and how each was resolved, with the exact error text.
6. Completed work.
7. Current state: what was in progress when this checkpoint was written.
8. Open tasks, explicit and implied.
9. Next step, consistent with the user's latest request.

For a role-play or character conversation, record instead: who the characters are and what has been established about them and the world, the state of their relationship, the tone and style of the conversation, and the story threads still open.

For every image or audio clip in the conversation, record what it was (its filename if one was given), what it showed or said, and what was concluded from it. It will not be available again.

For every file attached to the conversation (a document, text file, or spreadsheet), list under Artifacts its exact filename, and the name tools read it by if one was given (such as report.pdf.txt), what it is, its size or page count if known, which pages or parts mattered (with page numbers or offsets), and what was learned from it. The file may still be readable with tools, but its text above will not be, so record where to look rather than copying it out.

Do not invent facts. Do not restate the system prompt. When space runs short, keep corrections first, then errors, then work in progress, then completed work. Use at most about {{words}} words.

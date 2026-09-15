/**
 * The text of a confirmation form: the title line, then the confirmation code, then the
 * record the person confirms. Released clients fold long elicitation messages (Claude
 * Code 2.1.270 shows three lines and "+N more"), so the line the person must type from
 * sits at the top; every record line follows unchanged.
 */
export function confirmationFormMessage(lines: readonly string[]): string {
  const codeIndex = lines.findIndex((line) => line.startsWith("Confirmation code: "));
  if (codeIndex <= 1) return lines.join("\n");
  const [title, ...rest] = lines;
  const code = rest.splice(codeIndex - 1, 1);
  return [title, ...code, ...rest].join("\n");
}

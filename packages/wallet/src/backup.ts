/**
 * Mnemonic backup verification. The user must transcribe the recovery
 * phrase and then prove they did by supplying words at randomly chosen
 * positions — the wallet cannot be used until this passes, because evoevo
 * holds no custody and cannot recover a lost phrase.
 *
 * Randomness is injected (not drawn from Math.random) so the challenge is
 * deterministic in tests and so the caller controls entropy quality.
 */

export interface BackupChallenge {
  /** 1-indexed word positions the user must supply. */
  positions: number[];
}

/**
 * Builds a challenge asking for `count` distinct word positions. `pick`
 * returns a float in [0, 1) per call (e.g. a CSPRNG-backed function).
 */
export function buildBackupChallenge(
  mnemonic: string,
  count: number,
  pick: () => number,
): BackupChallenge {
  const total = mnemonic.trim().split(/\s+/).length;
  if (count < 1 || count > total) {
    throw new Error(`count must be between 1 and ${total}`);
  }
  const chosen = new Set<number>();
  // Rejection-sample distinct positions; bounded because count <= total.
  let guard = 0;
  while (chosen.size < count) {
    const position = Math.floor(pick() * total) + 1;
    chosen.add(position);
    if (++guard > total * 100) {
      throw new Error("could not draw distinct positions; check the pick function");
    }
  }
  return { positions: [...chosen].sort((a, b) => a - b) };
}

/**
 * Verifies the user's answers against the mnemonic. `answers` maps a
 * 1-indexed position to the word the user typed. Comparison is
 * case-insensitive and whitespace-trimmed; every challenged position must
 * be answered correctly.
 */
export function verifyBackup(
  mnemonic: string,
  challenge: BackupChallenge,
  answers: Record<number, string>,
): boolean {
  const words = mnemonic.trim().split(/\s+/);
  return challenge.positions.every((position) => {
    const expected = words[position - 1];
    const given = answers[position];
    return (
      expected !== undefined &&
      given !== undefined &&
      given.trim().toLowerCase() === expected.toLowerCase()
    );
  });
}

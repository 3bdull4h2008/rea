import type { HeaderArchitecture } from "./binaryTargetTypes.js";
import {
  readPeOptionalHeaderStructure,
  type PeOptionalHeaderStructure,
} from "./peOptionalHeader.js";
import { err, ok, type Result } from "./result.js";

export type PeArchitecture = Exclude<HeaderArchitecture, "hexagon">;

/** A decoded COFF machine and whether it carried a ReadyToRun OS override. */
export interface PeMachine {
  readonly architecture: PeArchitecture;
  readonly nativeOsOverride: boolean;
}

const architectureForMachine = (
  machine: number,
): PeArchitecture | undefined => {
  switch (machine) {
    case 0x014c:
      return "x86";
    case 0x8664:
      return "x86_64";
    case 0x01c0:
    case 0x01c2:
    case 0x01c4:
      return "arm";
    case 0xaa64:
      return "arm64";
    case 0x01c4: // ARM Thumb-2
    case 0x01f0: // IMAGE_FILE_MACHINE_POWERPC
    case 0x01f1: // IMAGE_FILE_MACHINE_POWERPCFP
    case 0x01f2: // IMAGE_FILE_MACHINE_POWERPCBE (Xbox 360 XEX)
    case 0x0200: // IMAGE_FILE_MACHINE_IA64
      return machine === 0x0200 ? "ia64" : "powerpc";
    case 0x0266: // MIPS16
    case 0x0166: // MIPS
    case 0x0169: // MIPS16FPU
    case 0x01a2: // SH3
    case 0x01a3: // SH3DSP
    case 0x01a4: // SH3E
    case 0x01a6: // SH4 (Dreamcast/PlayStation 2?)
    case 0x01a8: // SH5
    case 0x01c2:
    case 0x01c4:
      // already covered
      break;
  }
  // More comprehensive mapping
  if (machine === 0x014c) return "x86";
  if (machine === 0x8664) return "x86_64";
  if (machine === 0x01c0 || machine === 0x01c2 || machine === 0x01c4) return "arm";
  if (machine === 0xaa64) return "arm64";
  if (machine === 0x01f0 || machine === 0x01f1 || machine === 0x01f2) return "powerpc";
  if (machine === 0x0200) return "ia64";
  if (machine === 0x0266 || machine === 0x0166 || machine === 0x0169) return "mips";
  if (machine === 0x01a2 || machine === 0x01a3 || machine === 0x01a4 || machine === 0x01a6 || machine === 0x01a8) return "sh4";
  if (machine === 0x0001 || machine === 0x0162) return "m68k";
  if (machine === 0x0500) return "riscv";
  return undefined;
};

/** The optional-header magic a machine's architecture requires: PE32+ for 64-bit, PE32 otherwise. */
export const peOptionalHeaderMagic = (
  architecture: PeArchitecture,
): 0x10b | 0x20b =>
  architecture === "x86_64" || architecture === "arm64" ? 0x20b : 0x10b;

/**
 * ReadyToRun images compiled for a non-Windows OS store the COFF machine XORed
 * with IMAGE_FILE_MACHINE_NATIVE_OS_OVERRIDE (dotnet/runtime
 * src/coreclr/inc/pedecoder.h): Apple, FreeBSD, OpenBSD, Linux, NetBSD, SunOS.
 */
const NATIVE_OS_OVERRIDES = [0x4644, 0xadc4, 0xadc5, 0x7b79, 0x1993, 0x1992];

/**
 * Decode a COFF machine candidate. An OS override identifies an architecture
 * only after the optional header establishes a managed declaration.
 */
export const decodePeMachine = (machine: number): PeMachine | undefined => {
  const direct = architectureForMachine(machine);
  if (direct !== undefined)
    return { architecture: direct, nativeOsOverride: false };
  for (const override of NATIVE_OS_OVERRIDES) {
    const architecture = architectureForMachine(machine ^ override);
    if (architecture !== undefined)
      return { architecture, nativeOsOverride: true };
  }
  return undefined;
};

/**
 * Name a subject only when a direct COFF machine agrees with its declared PE
 * format. OS overrides need managed-header proof that these report facts lack;
 * unknown machines and conflicting optional-header widths also stay unknown.
 */
export const peSubjectArchitecture = (
  machineType: number,
  format: "pe32" | "pe32-plus",
): PeArchitecture | undefined => {
  const machine = decodePeMachine(machineType);
  if (machine === undefined || machine.nativeOsOverride) return undefined;
  const magic = format === "pe32-plus" ? 0x20b : 0x10b;
  return magic === peOptionalHeaderMagic(machine.architecture)
    ? machine.architecture
    : undefined;
};

/** Optional-header facts shared by admission and native metadata readers. */
export interface PeOptionalHeaderFacts extends PeOptionalHeaderStructure {
  readonly machine: PeMachine | null;
  readonly managed: boolean;
}

export interface PeHeaderFailure {
  readonly kind: "malformed" | "unsupported";
  readonly message: string;
}

/** Decode machine identity only when its optional header supplies the required proof. */
export const readPeOptionalHeader = (
  optionalHeader: Buffer,
  machineType: number,
): Result<PeOptionalHeaderFacts, PeHeaderFailure> => {
  const parsed = readPeOptionalHeaderStructure(optionalHeader);
  if (!parsed.ok)
    return err({ kind: parsed.error.kind, message: parsed.error.message });
  const facts = parsed.value;
  const cli = facts.dataDirectories[14];
  const managed = cli !== undefined && (cli.address !== 0 || cli.size !== 0);
  const decoded = decodePeMachine(machineType);
  // An encoded machine without a CLI declaration remains an unknown CPU to
  // metadata readers; admission separately rejects unsupported identities.
  const machine =
    decoded?.nativeOsOverride && !managed ? null : (decoded ?? null);
  if (
    machine !== null &&
    facts.magic !== peOptionalHeaderMagic(machine.architecture)
  )
    return err({
      kind: "malformed",
      message: "PE optional-header magic does not match its architecture",
    });
  return ok({ ...facts, machine, managed });
};

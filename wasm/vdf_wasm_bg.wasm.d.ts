/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const __wbg_vdfproof_free: (a: number, b: number) => void;
export const vdfproof_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint) => number;
export const vdfproof_y: (a: number) => [number, number];
export const vdfproof_pi: (a: number) => [number, number];
export const vdfproof_l: (a: number) => [number, number];
export const vdfproof_r: (a: number) => [number, number];
export const vdfproof_iterations: (a: number) => bigint;
export const vdfproof_to_json: (a: number) => [number, number, number, number];
export const vdfproof_from_json: (a: number, b: number) => [number, number, number];
export const __wbg_vdfcomputer_free: (a: number, b: number) => void;
export const vdfcomputer_new: () => number;
export const vdfcomputer_with_modulus: (a: number, b: number) => [number, number, number];
export const vdfcomputer_compute_proof: (a: number, b: number, c: number, d: bigint, e: number) => [number, number, number];
export const vdfcomputer_verify_proof: (a: number, b: number, c: number, d: number) => [number, number, number];
export const vdfcomputer_estimate_iterations_for_seconds: (a: number, b: number) => bigint;
export const benchmark_vdf: (a: number) => [number, number, number];
export const get_version: () => [number, number];
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_export_2: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;

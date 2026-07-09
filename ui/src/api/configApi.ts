import type { GatewayConfig } from "../types";
import { requestJson } from "./base";

export interface ConfigLoadAttempt {
  at: string;
  error: string | null;
}

export interface ConfigLoadStatus {
  state: "synced" | "drifted" | "failed";
  appliedGeneration: number | null;
  appliedAt: string | null;
  appliedHash: string | null;
  lastAttempt: ConfigLoadAttempt | null;
  storedMatchesApplied: boolean;
}

export function getConfig() {
  return requestJson<GatewayConfig>("/api/config");
}

export function getConfigLoadStatus() {
  return requestJson<ConfigLoadStatus>("/api/config/status");
}

export function writeConfig(config: GatewayConfig) {
  return requestJson<{ status: string; message: string }>("/api/config", {
    method: "POST",
    body: JSON.stringify(config),
  });
}

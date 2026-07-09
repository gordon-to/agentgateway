import type { GatewayConfig } from "../types";
import { requestJson } from "./base";

export interface ConfigLoadStatus {
  runningHash: string | null;
  diskHash: string | null;
  error: string | null;
  lastUpdatedAt: string | null;
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

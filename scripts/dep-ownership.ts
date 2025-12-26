/* eslint-disable no-console */

/// Ensure that all dependencies in package.json and Cargo.toml have an owner in the renovate.json5 file.

import fs from "fs";
import path from "path";

import JSON5 from "json5";
import TOML from "@iarna/toml";

const renovateConfig = JSON5.parse(
  fs.readFileSync(path.join(__dirname, "..", ".github", "renovate.json5"), "utf8"),
);

// Extract all packages with owners from renovate config
const packagesWithOwners = renovateConfig.packageRules
  .flatMap((rule: any) => rule.matchPackageNames)
  .filter((packageName: string) => packageName != null);

function hasOwner(packageName: string): boolean {
  return packagesWithOwners.includes(packageName);
}

// Collect npm dependencies
const packageJson = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"),
);
const npmDependencies = [
  ...Object.keys(packageJson.dependencies || {}),
  ...Object.keys(packageJson.devDependencies || {}),
];

// Collect Cargo dependencies from workspace Cargo.toml
const cargoToml = TOML.parse(
  fs.readFileSync(path.join(__dirname, "..", "Cargo.toml"), "utf8"),
) as any;

const cargoDependencies = new Set<string>();

// Extract from workspace.dependencies
if (cargoToml.workspace?.dependencies) {
  Object.keys(cargoToml.workspace.dependencies).forEach((depName) => {
    // Skip internal bitwarden crates
    if (!depName.startsWith("bitwarden")) {
      cargoDependencies.add(depName);
    }
  });
}

// Check for missing owners
const missingNpmOwners = npmDependencies.filter((dep) => !hasOwner(dep));
const missingCargoOwners = Array.from(cargoDependencies).filter((dep) => !hasOwner(dep));

const allMissing = [...missingNpmOwners, ...missingCargoOwners];

if (allMissing.length > 0) {
  console.error("Missing owners for the following dependencies:");
  if (missingNpmOwners.length > 0) {
    console.error("\nNPM dependencies:");
    console.error(missingNpmOwners.join("\n"));
  }
  if (missingCargoOwners.length > 0) {
    console.error("\nCargo dependencies:");
    console.error(missingCargoOwners.join("\n"));
  }
  process.exit(1);
}

console.log("All dependencies have owners.");

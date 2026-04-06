let masterKey = "";

export function setMasterKey(value) {
  masterKey = value || "";
}

export function getMasterKey() {
  return masterKey;
}

export function clearMasterKey() {
  masterKey = "";
}

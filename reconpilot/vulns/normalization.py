from __future__ import annotations


NVD_PRODUCT_ALIASES = {
    "unifi network": {
        "product_aliases": [
            "unifi network application",
            "unifi_network_application",
            "unifi_network_controller",
            "unifi network controller",
            "unifi controller",
            "ubiquiti unifi network",
        ],
        "vendor_aliases": ["ubiquiti", "ui"],
    },
}


def normalize_product_name(product):
    cleaned = " ".join(str(product or "").replace("_", " ").replace("-", " ").split()).strip()
    if not cleaned:
        return None
    lowered = cleaned.lower()
    aliases = {
        "apache httpd": "apache httpd",
        "apache": "apache httpd",
        "apache http server": "apache httpd",
        "http server": "apache httpd",
        "nginx": "nginx",
        "openssh": "openssh",
        "microsoft iis": "microsoft iis",
        "samba smbd": "samba",
        "samba": "samba",
        "vsftpd": "vsftpd",
        "php": "php",
    }
    if lowered in aliases:
        return aliases[lowered]
    if lowered.startswith("openssh "):
        return "openssh"
    if lowered.startswith("samba "):
        return "samba"
    return lowered


def normalize_version(version):
    cleaned = " ".join(str(version or "").split()).strip()
    return cleaned or None


def normalize_vendor_name(vendor):
    cleaned = " ".join(str(vendor or "").replace("_", " ").replace("-", " ").split()).strip()
    return cleaned.lower() or None


def build_nvd_aliases(product):
    normalized_product = normalize_product_name(product)
    if not normalized_product:
        return {"product_aliases": [], "vendor_aliases": []}

    product_aliases = [normalized_product]
    vendor_aliases = []

    if " " in normalized_product:
        product_aliases.append(normalized_product.replace(" ", "_"))
        product_aliases.append(f"{normalized_product} application")
    static_aliases = NVD_PRODUCT_ALIASES.get(normalized_product, {})
    product_aliases.extend(static_aliases.get("product_aliases", []))
    vendor_aliases.extend(static_aliases.get("vendor_aliases", []))

    deduped_products = []
    seen_products = set()
    for item in product_aliases:
        normalized_item = normalize_product_name(item)
        if not normalized_item or normalized_item in seen_products:
            continue
        seen_products.add(normalized_item)
        deduped_products.append(normalized_item)

    deduped_vendors = []
    seen_vendors = set()
    for item in vendor_aliases:
        normalized_item = normalize_vendor_name(item)
        if not normalized_item or normalized_item in seen_vendors:
            continue
        seen_vendors.add(normalized_item)
        deduped_vendors.append(normalized_item)

    return {"product_aliases": deduped_products, "vendor_aliases": deduped_vendors}


def build_software_identity(inventory_entry):
    display_product = " ".join(str(inventory_entry.get("product") or "").split()).strip()
    normalized_product = normalize_product_name(display_product)
    normalized_version = normalize_version(inventory_entry.get("version"))
    if not normalized_product or not normalized_version:
        return None
    return {
        "product": normalized_product,
        "display_product": display_product,
        "version": normalized_version,
        "source": inventory_entry.get("source") or inventory_entry.get("detection_source"),
        "confidence": inventory_entry.get("confidence"),
        "raw_evidence": inventory_entry.get("raw_evidence"),
        "cpe": inventory_entry.get("cpe"),
    }

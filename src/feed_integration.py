"""Threat intelligence feed integration module.

This module handles integration with external threat intelligence feeds
including STIX 2.0, MISP, and custom JSON feeds.
"""

import logging
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from src.database.models import ThreatSignature, DatabaseManager

logger = logging.getLogger(__name__)


class FeedIntegration:
    """Threat intelligence feed integration manager."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        config: Dict[str, Any] = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        """Initialize feed integration.

        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
            verify_ssl: Verify SSL certificates
            timeout: Request timeout in seconds
        """
        self.db_manager = db_manager
        self.config = config or {}
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._cache: Dict[str, Any] = {}
        self._cache_ttl: Dict[str, float] = {}

        # Check for optional dependencies
        self._has_requests = self._check_requests()
        self._has_misp = self._check_misp()
        self._has_stix = self._check_stix()

    def _check_requests(self) -> bool:
        """Check if requests library is available."""
        try:
            import requests
            import certifi

            return True
        except ImportError:
            logger.warning("requests/certifi not available - feed integration disabled")
            return False

    def _check_misp(self) -> bool:
        """Check if MISP library is available."""
        try:
            import pymisp

            return True
        except ImportError:
            logger.debug("pymisp not available - MISP integration disabled")
            return False

    def _check_stix(self) -> bool:
        """Check if STIX library is available."""
        try:
            import stix2

            return True
        except ImportError:
            logger.debug("stix2 not available - STIX integration disabled")
            return False

    def is_available(self) -> bool:
        """Check if feed integration is available.

        Returns:
            True if basic feed integration is available
        """
        return self._has_requests

    def update_all_feeds(self, sources: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Update all configured threat feeds.

        Args:
            sources: List of feed source configurations

        Returns:
            Dictionary with update results
        """
        if not self.is_available():
            logger.warning("Feed integration not available")
            return {"success": False, "error": "requests library not available"}

        results = {
            "success": True,
            "feeds_updated": 0,
            "feeds_failed": 0,
            "signatures_added": 0,
            "errors": [],
        }

        for source in sources:
            if not source.get("enabled", True):
                continue

            try:
                feed_result = self._update_feed(source)
                if feed_result["success"]:
                    results["feeds_updated"] += 1
                    results["signatures_added"] += feed_result.get("signatures_added", 0)
                else:
                    results["feeds_failed"] += 1
                    results["errors"].append(
                        {
                            "feed": source.get("name", "unknown"),
                            "error": feed_result.get("error", "unknown"),
                        }
                    )

            except Exception as e:
                logger.error(f"Error updating feed {source.get('name')}: {e}")
                results["feeds_failed"] += 1
                results["errors"].append({"feed": source.get("name", "unknown"), "error": str(e)})

        if results["feeds_failed"] > 0:
            results["success"] = False

        logger.info(
            f"Feed update complete: {results['feeds_updated']} succeeded, "
            f"{results['feeds_failed']} failed, "
            f"{results['signatures_added']} signatures added"
        )

        return results

    def _update_feed(self, source: Dict[str, Any]) -> Dict[str, Any]:
        """Update single threat feed.

        Args:
            source: Feed source configuration

        Returns:
            Dictionary with update result
        """
        feed_name = source.get("name", "unknown")
        feed_format = source.get("format", "json").lower()
        feed_url = source.get("url", "")

        logger.info(f"Updating feed: {feed_name} ({feed_format})")

        # Check cache
        cache_key = f"{feed_name}:{feed_url}"
        cache_ttl = self.config.get("cache_ttl", 86400)  # 24 hours default

        if cache_key in self._cache_ttl:
            if time.time() - self._cache_ttl[cache_key] < cache_ttl:
                logger.debug(f"Using cached data for {feed_name}")
                return {"success": True, "cached": True, "signatures_added": 0}

        try:
            if feed_format == "stix2":
                return self._update_stix_feed(source)
            elif feed_format == "misp":
                return self._update_misp_feed(source)
            elif feed_format == "json":
                return self._update_json_feed(source)
            else:
                return {"success": False, "error": f"Unsupported feed format: {feed_format}"}

        except Exception as e:
            logger.error(f"Error updating feed {feed_name}: {e}")
            return {"success": False, "error": str(e)}

    def _update_stix_feed(self, source: Dict[str, Any]) -> Dict[str, Any]:
        """Update STIX 2.0 feed.

        Args:
            source: Feed source configuration

        Returns:
            Update result
        """
        if not self._has_stix:
            return {"success": False, "error": "stix2 library not available"}

        import requests
        import stix2

        feed_url = source.get("url", "")
        feed_name = source.get("name", "unknown")

        try:
            response = requests.get(
                feed_url, timeout=self.timeout, verify=self.verify_ssl, headers={"User-Agent": "USBThreatDetection/1.0"}
            )
            response.raise_for_status()

            # Parse STIX bundle
            bundle = stix2.parse(response.text, allow_custom=True)
            signatures_added = 0

            for obj in bundle.objects:
                # Process indicators
                if obj.type == "indicator":
                    signature = self._stix_indicator_to_signature(obj, feed_name)
                    if signature:
                        self.db_manager.add_signature(signature)
                        signatures_added += 1

            # Update cache
            cache_key = f"{feed_name}:{feed_url}"
            self._cache_ttl[cache_key] = time.time()

            logger.info(f"STIX feed updated: {feed_name} ({signatures_added} signatures)")
            return {"success": True, "signatures_added": signatures_added}

        except Exception as e:
            logger.error(f"Error updating STIX feed {feed_name}: {e}")
            return {"success": False, "error": str(e)}

    def _stix_indicator_to_signature(
        self, indicator, source: str
    ) -> Optional[ThreatSignature]:
        """Convert STIX indicator to ThreatSignature.

        Args:
            indicator: STIX indicator object
            source: Feed source name

        Returns:
            ThreatSignature or None
        """
        try:
            pattern = getattr(indicator, "pattern", "")
            name = getattr(indicator, "name", "")
            description = getattr(indicator, "description", name)

            # Parse pattern to extract indicator type and value
            # Example: "[file:hashes.MD5 = 'abc123']"
            if "file:hashes" in pattern:
                # File hash indicator
                if "MD5" in pattern or "SHA" in pattern:
                    hash_value = pattern.split("'")[1] if "'" in pattern else ""
                    return ThreatSignature(
                        signature_type="file_hash",
                        indicator=hash_value,
                        description=description,
                        severity="medium",
                        source=source,
                    )
            elif "file:name" in pattern:
                # Filename indicator
                filename = pattern.split("'")[1] if "'" in pattern else ""
                return ThreatSignature(
                    signature_type="filename",
                    indicator=filename,
                    description=description,
                    severity="medium",
                    source=source,
                )

            # Generic indicator
            return ThreatSignature(
                signature_type="generic",
                indicator=pattern,
                description=description,
                severity="medium",
                source=source,
            )

        except Exception as e:
            logger.debug(f"Error converting STIX indicator: {e}")
            return None

    def _update_misp_feed(self, source: Dict[str, Any]) -> Dict[str, Any]:
        """Update MISP feed.

        Args:
            source: Feed source configuration

        Returns:
            Update result
        """
        if not self._has_misp:
            return {"success": False, "error": "pymisp library not available"}

        from pymisp import PyMISP

        misp_url = source.get("url", "")
        api_key = source.get("api_key", "")
        feed_name = source.get("name", "unknown")

        if not api_key:
            return {"success": False, "error": "MISP API key not configured"}

        try:
            misp = PyMISP(misp_url, api_key, self.verify_ssl)

            # Search for recent USB-related events
            events = misp.search(tags=["usb", "malware"], limit=100, pythonify=True)
            signatures_added = 0

            for event in events:
                for attribute in event.attributes:
                    signature = self._misp_attribute_to_signature(attribute, feed_name)
                    if signature:
                        self.db_manager.add_signature(signature)
                        signatures_added += 1

            # Update cache
            cache_key = f"{feed_name}:{misp_url}"
            self._cache_ttl[cache_key] = time.time()

            logger.info(f"MISP feed updated: {feed_name} ({signatures_added} signatures)")
            return {"success": True, "signatures_added": signatures_added}

        except Exception as e:
            logger.error(f"Error updating MISP feed {feed_name}: {e}")
            return {"success": False, "error": str(e)}

    def _misp_attribute_to_signature(self, attribute, source: str) -> Optional[ThreatSignature]:
        """Convert MISP attribute to ThreatSignature.

        Args:
            attribute: MISP attribute object
            source: Feed source name

        Returns:
            ThreatSignature or None
        """
        try:
            attr_type = attribute.type
            value = attribute.value
            comment = getattr(attribute, "comment", "")

            # Map MISP attribute types to signature types
            type_mapping = {
                "md5": "file_hash",
                "sha1": "file_hash",
                "sha256": "file_hash",
                "filename": "filename",
                "domain": "domain",
                "url": "url",
                "ip-dst": "ip_address",
            }

            sig_type = type_mapping.get(attr_type, "generic")

            return ThreatSignature(
                signature_type=sig_type,
                indicator=value,
                description=comment or f"MISP {attr_type} indicator",
                severity="medium",
                source=source,
            )

        except Exception as e:
            logger.debug(f"Error converting MISP attribute: {e}")
            return None

    def _update_json_feed(self, source: Dict[str, Any]) -> Dict[str, Any]:
        """Update custom JSON feed.

        Args:
            source: Feed source configuration

        Returns:
            Update result
        """
        import requests

        feed_url = source.get("url", "")
        feed_name = source.get("name", "unknown")

        try:
            response = requests.get(
                feed_url, timeout=self.timeout, verify=self.verify_ssl, headers={"User-Agent": "USBThreatDetection/1.0"}
            )
            response.raise_for_status()

            data = response.json()
            signatures_added = 0

            # Expected format: list of indicator objects
            indicators = data if isinstance(data, list) else data.get("indicators", [])

            for indicator in indicators:
                try:
                    signature = ThreatSignature(
                        signature_type=indicator.get("type", "generic"),
                        indicator=indicator.get("value", ""),
                        description=indicator.get("description", ""),
                        severity=indicator.get("severity", "medium"),
                        source=feed_name,
                    )
                    self.db_manager.add_signature(signature)
                    signatures_added += 1
                except Exception as e:
                    logger.debug(f"Error processing indicator: {e}")
                    continue

            # Update cache
            cache_key = f"{feed_name}:{feed_url}"
            self._cache_ttl[cache_key] = time.time()

            logger.info(f"JSON feed updated: {feed_name} ({signatures_added} signatures)")
            return {"success": True, "signatures_added": signatures_added}

        except Exception as e:
            logger.error(f"Error updating JSON feed {feed_name}: {e}")
            return {"success": False, "error": str(e)}

    def clear_cache(self):
        """Clear feed cache."""
        self._cache.clear()
        self._cache_ttl.clear()
        logger.info("Feed cache cleared")

    def get_feed_status(self) -> Dict[str, Any]:
        """Get status of feed integration.

        Returns:
            Status dictionary
        """
        return {
            "available": self.is_available(),
            "requests": self._has_requests,
            "misp": self._has_misp,
            "stix": self._has_stix,
            "cached_feeds": len(self._cache_ttl),
        }

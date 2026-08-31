def scan_browser_storage(page) -> dict:
    """
    Scan browser storage accessible
    from the current page.
    """

    local_storage = page.evaluate(
        """
        () => {
            const result = {};

            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                result[key] = localStorage.getItem(key);
            }

            return result;
        }
        """
    )

    session_storage = page.evaluate(
        """
        () => {
            const result = {};

            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                result[key] = sessionStorage.getItem(key);
            }

            return result;
        }
        """
    )

    indexed_db = page.evaluate(
        """
        async () => {
            if (!window.indexedDB ||
                !indexedDB.databases) {
                return [];
            }

            try {
                const databases =
                    await indexedDB.databases();

                return databases.map(
                    database => ({
                        name: database.name,
                        version: database.version
                    })
                );

            } catch (error) {
                return [];
            }
        }
        """
    )

    cache_storage = page.evaluate(
        """
        async () => {

            if (!window.caches) {
                return [];
            }

            try {
                return await caches.keys();

            } catch (error) {
                return [];
            }
        }
        """
    )

    service_workers = page.evaluate(
        """
        async () => {

            if (!navigator.serviceWorker) {
                return [];
            }

            try {

                const registrations =
                    await navigator
                        .serviceWorker
                        .getRegistrations();

                return registrations.map(
                    registration => ({
                        scope: registration.scope,
                        active:
                            registration.active
                            ? registration.active.scriptURL
                            : null,
                        waiting:
                            registration.waiting
                            ? registration.waiting.scriptURL
                            : null,
                        installing:
                            registration.installing
                            ? registration.installing.scriptURL
                            : null
                    })
                );

            } catch (error) {
                return [];
            }
        }
        """
    )

    return {
        "local_storage": local_storage,

        "session_storage": session_storage,

        "indexed_db": indexed_db,

        "cache_storage": cache_storage,

        "service_workers": service_workers,
    }


def storage_summary(storage: dict) -> dict:
    """
    Generate storage statistics.
    """

    return {
        "local_storage_items": len(
            storage.get("local_storage", {})
        ),

        "session_storage_items": len(
            storage.get("session_storage", {})
        ),

        "indexed_db_databases": len(
            storage.get("indexed_db", [])
        ),

        "cache_storage_entries": len(
            storage.get("cache_storage", [])
        ),

        "service_workers": len(
            storage.get("service_workers", [])
        ),
    }
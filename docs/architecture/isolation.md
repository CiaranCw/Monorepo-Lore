# Repository isolation

List, search, batch, and repository-id lookup use the caller's grants on the server. An unauthorized id and an unknown id both return not found. Batch results do not echo names the caller cannot access.

The same module name in two projects is two repository ids. A grant in one project does not apply to the other.

The publisher service account can resolve parent repositories and archived modules so historical pins remain fetchable. Human lists do not include those ids.

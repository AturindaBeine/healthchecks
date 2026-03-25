## Comparing AI-Generated logging suggestions with Human reasoning. 

Logging was added in the `hc/api/views.py` and AI and human reasoning agreed and disagreed in various ways. 

They both agreed in the following ways:
1. A logger needed to be added in the file
2. Check deleted, paused or resumed since these change the system state and need an audit trail.
3. A warning is required when one project accesses another project's checks since it could be a leaked or misconfigured API key.
4. Each incoming ping should be logged because it is useful for debugging.

However, AI-Generated logging suggestions did not agree with human reasoning in the following areas:
1. AI may focus more on what is happening to the system but human reasoning focuses more on what a failure means to the user or business.
2. AI-Generated logging suggests using "info" to create an audit trail that can be traceable while human reason would look at using "debug" because if checks are deleted, logging each deleted check at "info" would flood the logs with entries that no one would actually act on.

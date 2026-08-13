# Scope Templates by a caller-provided Session Key

The Template Store will identify Templates by `(Session Key, Observation Domain ID, Template ID)`, with explicit Session reset and RFC withdrawal operations. Inferring identity from addresses would couple the portable decoder to a transport adapter, while omitting Session scope could apply one exporter session's Template to another session's Data Records.

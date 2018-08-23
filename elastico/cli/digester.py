'''idea of digest commands is to analyse and do digestions.

Here an example for aggregating filesystem metricset of metric beat:

Configuration:
```yaml
# for each index matching index pattern
retentions:
- index-pattern: metricbeat-*

  target: history-metricbeat-%Y-%m

  digest:
  - name: metricset-filesystem

    fields:
        metricset.module: "system"
        metricset.name: "filesystem"

    buckets:
        terms:
            tags:        tags
            host_name:   host.name
            mount_point: system.filesystem.mount_point

    aggregate:
        terms:
            metricset.name:   metricset.name
            metricset.module: metricset.module
        stats:
            available:  system.filesystem.available
            free:       system.filesystem.free
            total:      system.filesystem.total
            available:  system.filesystem.available
            used_pct:   system.filesystem.used.pct
            used_bytes: system.filesystem.used.bytes

  - name: metricset-network

      fields:
        metricset.module: "system"
        metricset.name: "filesystem"

      buckets:
        terms:
          - host.name
          - system.network.name

      aggregate:
        terms:
            - tags
        stats:
            - system.network.in.bytes
            - system.network.in.dropped
            - system.network.in.errors
            - system.network.in.packats

            - system.network.out.bytes
            - system.network.out.dropped
            - system.network.out.errors
            - system.network.out.packats
```

```json
```


'''
from .cli import command

digester_command = command.add_subcommands('digester',)

digester_command('query',
)

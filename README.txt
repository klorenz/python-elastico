# Elastico -- the Elasticsearch Companion or Elasticsearch Command-line Client

## Search

This is a simple interface for searches.  You can do quick commandline

## Elastico alerter

Elastico alerter is a simple system for alerting on the base of
elasticsearch queries.  It maintains its status in the same elasticsearch
index, which it queries or in a given directory.

You run it with:

```bash
elastico -C /path/to/config.yaml alerter run
```


## Configuration

Configuration is YAML formatted and read from file or stdin.  A
configuration file consists of some global settings and settings corresponding to subcommand.  So configurations related to alerter are found under key `alerter`.

You can use format strings referring to other items of the configuration
file which are expanded as soon the context has all needed values.

### Including other files

You can include other files to organize your configurations. You can either include a single file or all files in a directory.  The included data can be either appended to a list or it can update a dictionary.  Relative paths are relative to the current
configuration yaml file.

When reading a yaml file, all includes in the main section are
evaluated.  When appending data, you can have multi-document YAML
files.  Each document will be appended on its own.

Example:

```
includes:
- file: path/to/file.yml
  update: foo.bar
- directory: path/to/dir
  append: foo.data

foo:
  bar: {}
  data: []
```

### Global settings

- `at`

   Simulate the script running at a point in time.  This helps to test
   temporal queries, which are relative to run-date.

- `alerter.serve.sleep_seconds`

  Set sleep time between runs in server mode.

- `alerter.alert_defaults`

  This is a dictionary having each alert type as key, defining default
  values for populating alerts, which can be overwritten in a concrete alert
  configuration.

- `alerter.status_storage`

   This is either "elasticsearch" or "memory" or "filesystem".  Default is
   "memory".

- `alerter.status_storage_path`

  If `status_storage` is "filesystem", this is a path to a directory, where
  status will be stored.

- `elasticsearch`

  This parameter gets the arguments, which are usually passes to
  `elasticsearch.Elasticsearch` constructor.  You can leave this empty to
  connect to default localhost.

  ```yaml
  elasticsearch:
    hosts:
    - http://localhost:9200
  ```

- `netrc`

  Instead of putting login data into configuration file you can also use the
  common `.netrc` mechanism to store username and password in an external
  file:

  ```yaml
  netrc: foo
  ```

  This will look in `.netrc` for an entry like:

  ```
  machine foo login user password pass
  ```

  If you want to name a netrc file instead of the user's default:

  ```yaml
  netrc:
    file: path/to/netrc/file
    machine: foo
  ```


### Rule configuration

- `foreach`

  Define some parameters, which produce more alert rules from a single
  rule for each combination of foreach items.

  **Example**

  You want to alert, if diskspace on servers is running low.  Mountpoints
  are on servers are configured in a uniform way.  In this example you find also a reference to some other data, which will be expanded when evaluating the `foreach` clause.  

  It works pretty much like the regular YAML expansion with the difference, that the data needs not to be in the same YAML file, but can be at a different place of the config file.

  ```yaml
  data:
    hosts:
      - foo
      - bar

  alerter:
    rules:

    - name: diskspace-servers {host_name} {mount_point}

      foreach:
        host_name: "*data.hosts"
        mount_point:
          - /
          - /home
          - /var

      warning_size: 10000000000
      fatal_size:    5000000000

      alerts:
        warning:
          match: >
            host.name: {host_name}
            AND system.filesystem.mount_point: "{mount_point}"
            AND system.filesystem.free:[{fatal_size} TO {warning_size}]

        fatal:
          match: >
            host.name: {host_name}
            AND system.filesystem.mount_point: "{mount_point}"
            AND system.filesystem.free:[0 TO {fatal_size}]
  ```

  As you can see there are strings with format data.  They will be expanded
  on demand.


### Alert configuration

You can define your types on your own.  The type of the alert and what is done
at an alert, can be freely configured.

Here are listed the keys and values, which are needed from alerter to process
and raise the alerts:

- `type`

  **Mandatory**. Type of the alert.  Usually something like `warning`, `fatal`
  or however you name your alerts.

- `key`

  If there is a `foreach` key, this is mandatory.  Else optional.  This is used
  for identifying an alert in combination with `type` in elasticsearch index
  or in filesystem.

- `realert`

  Dictionary as keyword args for [timedelta], could have `hours`, `minutes`,
  `seconds`, `days` as keys.

  **Example**

  ```yaml
  realert:
    minutes: 60
  ```

  [timedelta]: https://docs.python.org/2/library/datetime.html#timedelta-objects

- `notify`

  This is a list of actions done to alert configurations to actually do something for alerting.

  See

  There are following alert types:

  - `email`






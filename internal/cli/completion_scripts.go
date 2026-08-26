package cli

// Generated completion scripts. Kept dependency-free: the scripts embed
// the command list directly.

const bashCompletion = `# bash completion for botjim
_botjim() {
  local cur prev cmds
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmds="server send pull relay recv swarm serve update audit config version help"
  case "${COMP_WORDS[1]}" in
    server) COMPREPLY=( $(compgen -W "--bind --root --port --map-owners --parallel --no-fsync --no-tui --token --pass --cloak -q -v --log-file --audit --audit-file" -- "$cur") );;
    send) COMPREPLY=( $(compgen -W "--via --code --port --dest --compress --zstd-level --parallel --map-owners --no-xattr --no-sparse --devices --one-file-system --resume --no-fsync --stop-on-error --probe --token --pass --cloak --limit --retries --dry-run --exclude --include --json --delete --no-tui -q -v --log-file --audit --audit-file" -- "$cur") );;
    pull) COMPREPLY=( $(compgen -W "--port --dest --compress --zstd-level --parallel --map-owners --no-xattr --no-sparse --devices --one-file-system --resume --no-fsync --stop-on-error --probe --token --pass --cloak --limit --retries --dry-run --exclude --include --json --delete --no-tui -q -v --log-file --audit --audit-file" -- "$cur") );;
    relay) COMPREPLY=( $(compgen -W "--bind --port --wait --spool-max --spool-mem --spool-dir --no-spool-disk" -- "$cur") );;
    recv) COMPREPLY=( $(compgen -W "--via --code --dest --map-owners --parallel --no-fsync --no-tui -q -v --log-file --audit --audit-file" -- "$cur") );;
    swarm)
      case "${COMP_WORDS[2]}" in
        seed) COMPREPLY=( $(compgen -W "--tracker --code --port --name" -- "$cur") );;
        join) COMPREPLY=( $(compgen -W "--tracker --code --spec --dest --parallel --serve" -- "$cur") );;
        track) COMPREPLY=( $(compgen -W "--port" -- "$cur") );;
        *) COMPREPLY=( $(compgen -W "seed join track verify" -- "$cur") );;
      esac;;
    serve) COMPREPLY=( $(compgen -W "--bind --port --root" -- "$cur") );;
    update) COMPREPLY=( $(compgen -W "--check --force --version --repo" -- "$cur") );;
    audit)
      case "${COMP_WORDS[2]}" in
        verify|tail) ;;
        *) COMPREPLY=( $(compgen -W "verify tail" -- "$cur") );;
      esac;;
    config)
      case "${COMP_WORDS[2]}" in
        path|show) ;;
        *) COMPREPLY=( $(compgen -W "path show" -- "$cur") );;
      esac;;
    *)
      if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
      fi
      ;;
  esac
  return 0
}
complete -F _botjim botjim
`

const zshCompletion = `#compdef botjim
_botjim() {
  local -a cmds
  cmds=(
    'server:wait for transfers'
    'send:push files'
    'pull:pull files'
    'relay:pairing broker'
    'recv:relay receive'
    'swarm:swarm distribution'
    'serve:HTTP bridge'
    'update:self-update'
    'audit:journal reader'
    'config:config file'
    'version:print version'
    'help:usage'
  )
  if (( CURRENT == 2 )); then
    _describe 'command' cmds
    return
  fi
  case $words[2] in
    send|pull)
      _arguments '*: :->files' \
        '--via[relay]' '--code[pairing code]' '--compress[none|zstd|lz4]' \
        '--parallel[n]' '--resume[on|size|fresh]' '--limit[bytes]' \
        '--retries[n]' '--dry-run[plan only]' '--exclude[pat]' '--include[pat]' \
        '--json[NDJSON events]' '--delete[mirror]' '--token[t]' '--pass[t]' '--cloak[path]'
      _files
      ;;
    server)
      _arguments '--root[dir]' '--port[n]' '--bind[addr]' '--token[t]' '--pass[t]' '--cloak[path]'
      ;;
    *)
      _files
      ;;
  esac
}
_botjim "$@"
`

const fishCompletion = `# fish completion for botjim
complete -c botjim -n '__fish_use_subcommand' -a 'server send pull relay recv swarm serve update audit config version help'
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l via -d 'relay through RELAY'
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l code -d 'pairing code'
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l compress -d 'none|zstd|lz4'
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l parallel -d 'streams'
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l resume -d 'on|size|fresh'
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l limit -d 'rate cap'
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l retries -d 'auto-reconnect'
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l dry-run -d 'plan only'
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l exclude
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l include
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l json -d 'NDJSON events'
complete -c botjim -n '__fish_seen_subcommand_from send pull' -l delete -d 'mirror'
complete -c botjim -n '__fish_seen_subcommand_from send pull server' -l token
complete -c botjim -n '__fish_seen_subcommand_from send pull server' -l pass
complete -c botjim -n '__fish_seen_subcommand_from send pull server' -l cloak -d 'ws path'
complete -c botjim -n '__fish_seen_subcommand_from server' -l root -d 'jail dir'
complete -c botjim -n '__fish_seen_subcommand_from server' -l port
complete -c botjim -n '__fish_seen_subcommand_from swarm' -a 'seed join track verify'
`

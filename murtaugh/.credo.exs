%{
  configs: [
    %{
      name: "default",
      checks: %{
        extra: [
          # Ingest modules share the `case lookup -> with_tenant(fn -> ...)` shape,
          # which is inherently three levels deep.
          {Credo.Check.Refactor.Nesting, max_nesting: 3}
        ]
      }
    }
  ]
}

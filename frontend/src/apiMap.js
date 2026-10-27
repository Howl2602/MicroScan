export function getApiMapPath(endpoint) {
  const candidates = [endpoint?.path, endpoint?.url, endpoint?.target, endpoint?.template]
  for (const value of candidates) {
    if (typeof value !== 'string' || !value.trim()) continue
    const candidate = value.trim()
    let path = candidate
    if (/^https?:\/\//i.test(candidate)) {
      try {
        const parsed = new URL(candidate)
        if (!parsed.hostname) continue
        path = candidate.match(/^https?:\/\/[^/?#]+([^?#]*)/i)?.[1] || '/'
      } catch {
        continue
      }
    } else if (/^[a-z][a-z\d+.-]*:/i.test(candidate) || candidate.startsWith('//')) {
      continue
    }

    path = path.split(/[?#]/, 1)[0]
    if (!path) continue
    return path.startsWith('/') ? path : `/${path}`
  }
  return null
}

export function getDiscoveryCategory(endpoint) {
  const status = Number(
    endpoint?.status_code ?? endpoint?.responses?.[0]?.sc ?? endpoint?.status,
  )
  const verification = endpoint?.verification_status
  if (verification === 'not_found') return 'not_found'
  if (verification === 'blocked') return 'blocked'
  if (verification === 'inconclusive') return 'inconclusive'
  if (status === 404) return 'not_found'
  if (status === 401 || status === 403) return 'blocked'
  if (status === 405) return 'inconclusive'
  return 'actionable'
}

export function filterDiscoveryResults(results = [], category = 'actionable') {
  if (!Array.isArray(results)) return []
  if (category === 'all') return results
  return results.filter((item) => getDiscoveryCategory(item) === category ||
    (category === 'actionable' && getDiscoveryCategory(item) !== 'not_found'))
}

function getApiMapOrigin(endpoint) {
  for (const value of [endpoint?.resolved_url, endpoint?.verification_url, endpoint?.url]) {
    if (typeof value !== 'string' || !value.trim()) continue
    try {
      const parsed = new URL(value)
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return parsed.origin
      }
    } catch {
      continue
    }
  }
  return 'Unresolved origin'
}

export function buildApiTree(results = [], category = 'actionable') {
  const root = Object.create(null)
  if (!Array.isArray(results)) return root

  filterDiscoveryResults(results, category).forEach((result) => {
    const path = getApiMapPath(result)
    if (!path) return
    const origin = getApiMapOrigin(result)
    if (!Object.hasOwn(root, origin)) {
      root[origin] = {
        children: Object.create(null),
        endpoints: [],
      }
    }
    const parts = path.split('/').filter(Boolean)

    let current = root[origin].children
    let endpointNode = null

    parts.forEach((part) => {
      if (!Object.hasOwn(current, part)) {
        current[part] = {
          children: Object.create(null),
          endpoints: [],
        }
      }

      endpointNode = current[part]
      current = current[part].children
    })

    if (endpointNode) {
      endpointNode.endpoints.push(result)
    } else {
      root[origin].endpoints.push(result)
    }
  })

  return root
}

import assert from 'node:assert/strict'
import test from 'node:test'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { fileURLToPath } from 'node:url'
import { createServer } from 'vite'

import {
  buildApiTree,
  filterDiscoveryResults,
  getApiMapPath,
  getDiscoveryCategory,
} from '../src/apiMap.js'

function flattenTree(node, values = []) {
  Object.values(node).forEach((item) => {
    values.push(...item.endpoints)
    flattenTree(item.children, values)
  })
  return values
}

test('API Map groups initial and seeded discovery inventory records by path', () => {
  const inventory = [
    {
      url: 'http://localhost:8085/api/users',
      method: 'GET',
      status_code: 200,
      sources: ['kiterunner'],
    },
    {
      url: 'http://localhost:8085/api/orders',
      method: 'GET',
      sources: ['kiterunner_seeded', 'javascript'],
    },
    {
      url: 'http://localhost:8085/api/orders/42',
      method: 'GET',
      status_code: 403,
      sources: ['javascript'],
      verification_status: 'blocked',
    },
  ]

  const tree = buildApiTree(inventory)

  assert.deepEqual(
    flattenTree(tree).map((endpoint) => getApiMapPath(endpoint)).sort(),
    ['/api/orders', '/api/orders/42', '/api/users'],
  )
  assert.deepEqual(
    flattenTree(tree).find((endpoint) => endpoint.sources.includes('kiterunner_seeded'))
      .sources,
    ['kiterunner_seeded', 'javascript'],
  )
})

test('API Map accepts partial records and preserves different methods', () => {
  const tree = buildApiTree([
    { url: 'http://localhost:8085/api/items', method: 'GET' },
    { path: '/api/items', method: 'POST', sources: ['javascript'] },
    { method: 'GET' },
    null,
  ])

  const endpoints = flattenTree(tree)
  assert.equal(endpoints.length, 2)
  assert.deepEqual(
    endpoints.map((endpoint) => endpoint.method).sort(),
    ['GET', 'POST'],
  )
})

test('API Map builds a 24-result inventory with unresolved endpoints and evidence', () => {
  const inventory = Array.from({ length: 24 }, (_, index) => ({
    url: `http://localhost:${index % 2 ? 3000 : 8085}/api/resource-${index}`,
    method: index % 2 ? 'GET' : 'POST',
    status_code: index % 3 === 0 ? null : 200,
    verification_status: index % 3 === 0 ? 'discovered' : 'verified',
    security_status: index % 4 === 0 ? 'skipped' : 'tested',
    sources: index % 5 === 0 ? null : ['javascript'],
    evidence: index % 6 === 0
      ? null
      : [{ source_url: 'http://localhost:3000/assets/app.js', snippet: `fetch('/api/resource-${index}')` }],
  }))
  inventory.push({
    url: null,
    template: '/api/orders/${encodeURIComponent(id)}',
    method: 'GET',
    verification_status: 'discovered',
    resolution_status: 'unresolved',
    sources: ['javascript'],
    evidence: [{ source_url: 'http://localhost:3000/assets/app.js', snippet: 'dynamic path' }],
  })

  const tree = buildApiTree(inventory)
  const endpoints = flattenTree(tree)

  assert.equal(endpoints.length, 25)
  assert.equal(endpoints.filter((endpoint) => endpoint.method === 'POST').length, 12)
  assert.ok(endpoints.some((endpoint) => getApiMapPath(endpoint) === '/api/orders/${encodeURIComponent(id)}'))
  assert.ok(endpoints.some((endpoint) => endpoint.security_status === 'skipped'))
})

test('API Map component renders the 24-result inventory after scan completion', async () => {
  const server = await createServer({
    configFile: fileURLToPath(new URL('../vite.config.js', import.meta.url)),
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
  })

  try {
    const { ApiTreeNode } = await server.ssrLoadModule('/src/App.jsx')
    const inventory = Array.from({ length: 24 }, (_, index) => ({
      url: `http://localhost:${index % 2 ? 3000 : 8085}/api/resource-${index}`,
      method: index % 2 ? 'GET' : 'POST',
      verification_status: index % 3 ? 'verified' : 'discovered',
      security_status: index % 4 ? 'tested' : 'skipped',
      sources: index % 5 ? ['javascript'] : null,
      evidence: index % 6
        ? [{ source_url: 'http://localhost:3000/assets/app.js', snippet: 'fetch(...)' }]
        : null,
    }))
    const html = renderToStaticMarkup(
      createElement(ApiTreeNode, { node: buildApiTree(inventory) }),
    )

    assert.equal((html.match(/>GET</g) ?? []).length, 12)
    assert.equal((html.match(/>POST</g) ?? []).length, 12)
    assert.match(html, /\/api\/resource-23/)
    assert.match(html, /Verification: discovered/)
    assert.match(html, /Security: skipped/)
  } finally {
    await server.close()
  }
})

test('API Map ignores malformed URLs and non-array results without throwing', () => {
  const tree = buildApiTree([
    { url: 'http://[invalid' },
    { url: 'javascript:alert(1)' },
    { url: null },
    null,
  ])

  assert.equal(Object.keys(tree).length, 0)
  assert.equal(Object.keys(buildApiTree(null)).length, 0)
  assert.equal(getApiMapPath({ url: 'http://[invalid' }), null)
})

test('API Map retains unresolved dynamic URL templates as display paths', () => {
  const template = '/api/orders/${encodeURIComponent(id)}'
  assert.equal(getApiMapPath({ url: null, template }), template)
  assert.equal(getApiMapPath({ url: 'http://[invalid', template }), template)
})

test('API Map returns an empty tree for empty or unusable inventory', () => {
  assert.equal(Object.keys(buildApiTree([])).length, 0)
  assert.equal(Object.keys(buildApiTree([{ method: 'GET' }, { url: null }])).length, 0)
})

test('API Map excludes normalized not-found records by default and exposes audit filters', () => {
  const inventory = [
    { url: 'http://localhost:8085/api/missing', method: 'GET', status_code: '404' },
    {
      url: 'http://localhost:8085/api/fallback',
      method: 'GET',
      status_code: 200,
      verification_status: 'not_found',
      verification_reason: 'Frontend HTML fallback',
    },
    { url: 'http://localhost:8085/api/inventory', method: 'GET', status_code: 401 },
    { url: 'http://localhost:8085/api/admin', method: 'GET', status_code: 403 },
    { url: 'http://localhost:8085/api/auth/login', method: 'GET', status_code: 405 },
    {
      url: 'http://localhost:8085/api/known',
      method: 'GET',
      status_code: 404,
      verification_status: 'inconclusive',
    },
  ]

  assert.deepEqual(
    filterDiscoveryResults(inventory).map((endpoint) => getApiMapPath(endpoint)).sort(),
    ['/api/admin', '/api/auth/login', '/api/inventory', '/api/known'],
  )
  assert.equal(filterDiscoveryResults(inventory, 'not_found').length, 2)
  assert.equal(filterDiscoveryResults(inventory, 'blocked').length, 2)
  assert.equal(filterDiscoveryResults(inventory, 'inconclusive').length, 2)
  assert.equal(getDiscoveryCategory(inventory[5]), 'inconclusive')
  assert.equal(
    flattenTree(buildApiTree(inventory)).some((endpoint) => getApiMapPath(endpoint) === '/api/missing'),
    false,
  )
  assert.equal(
    flattenTree(buildApiTree(inventory, 'not_found')).length,
    2,
  )
})

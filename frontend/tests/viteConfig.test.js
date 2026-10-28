import assert from 'node:assert/strict'
import test from 'node:test'
import viteConfig from '../vite.config.js'

test('dev and preview APIs use a port-independent same-origin proxy', () => {
  const config = viteConfig({ mode: 'test' })
  const devProxy = config.server.proxy['/api']
  const previewProxy = config.preview.proxy['/api']

  assert.ok(devProxy.target)
  assert.equal(devProxy.rewrite('/api/scan'), '/scan')
  assert.equal(previewProxy.target, devProxy.target)
  assert.equal(previewProxy.rewrite('/api/file-discovery'), '/file-discovery')
})

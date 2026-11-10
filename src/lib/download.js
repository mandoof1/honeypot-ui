/**
 * Hand a downloaded body to the browser as a file. The object URL is released
 * a moment later: revoking it in the same tick cancels the save in some
 * browsers.
 */
export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

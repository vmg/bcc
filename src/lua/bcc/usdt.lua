--[[
Copyright 2016 GitHub, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]
local ffi = require("ffi")
ffi.cdef "void free(void *ptr);"

local libbcc = require("bcc.libbcc")
local Usdt = class("USDT")

Usdt.static.open_contexts = {}

function Usdt.static.cleanup()
  for _, context in ipairs(Usdt.static.open_contexts) do
    context:_cleanup()
  end
end

function Usdt:initialize(args)
  assert(args.text)
  assert(args.pid or args.path)

  if args.pid then
    self.pid = args.pid
    self.context = libbcc.bcc_usdt_new_frompid(args.pid)
  elseif args.path then
    self.path = args.path
    self.context = libbcc.bcc_usdt_new_frompath(args.path)
  end

  assert(self.context ~= nil, "failed to create USDT context")

  self.enabled = {}
  self.text = args.text

  table.insert(Usdt.open_contexts, self)
end

function Usdt:enable_probe(args)
  assert(args.probe and args.fn_name)

  local pfd = libbcc.bcc_usdt_find_probe(self.context, args.probe)
  assert(pfd >= 0, "failed to find probe %s" % args.probe)

  local bpgen = libbcc.bcc_usdt_probe_boilerplate(self.context, pfd)
  assert(bpgen ~= nil, "failed to generate USDT probe text")
  self.text = ffi.string(bpgen) .. self.text
  ffi.C.free(bpgen)

  if libbcc.bcc_usdt_probe_need_enable(self.context, pfd) == 1 then
    assert(libbcc.bcc_usdt_probe_enable(self.context, pfd) == 0,
      "failed to enable probe in PID %d" % self.pid)
    log.info("usdt semaphore enabled at PID %d", self.pid)
  end

  self.enabled[pfd] = args.fn_name
end

function Usdt:_cleanup()
  for pfd, _ in pairs(self.enabled) do
    if libbcc.bcc_usdt_probe_need_enable(self.context, pfd) == 1 then
      assert(libbcc.bcc_usdt_probe_disable(self.context, pfd) == 0)
      log.info("usdt semaphore disabled at PID %d", self.pid)
    end
  end
end

function Usdt:_attach_uprobes(bpf)
  for pfd, fn_name in pairs(self.enabled) do
    local binpath = ffi.string(
      libbcc.bcc_usdt_probe_binpath(self.context, pfd))
    local n_locations = libbcc.bcc_usdt_probe_location_count(self.context, pfd)

    for loc = 0, tonumber(n_locations)-1 do
      local address = libbcc.bcc_usdt_probe_address(self.context, pfd, loc)
      bpf:attach_uprobe{name=binpath, addr=address, fn_name=fn_name}
    end
  end
end

return Usdt

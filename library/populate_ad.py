#!/usr/bin/python

# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Based on https://github.com/dericcrago/ansible/blob/6d6dea0881fe79e7b6c605a916266139dc4d15d7/lib/ansible/modules/cloud/vmware/vmware_guest.py
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import time

DOCUMENTATION = r'''
---
module: populate_ad
short_description: Manages virtual machines in vCenter
description:
- Create new floppy disk.
- Modify, rename or remove a floppy disk.
version_added: '2.14.2'
author:
- Helvio Junior (@helviojunior)
notes:
- Tested on vSphere 7.0 U2
requirements:
- python >= 3.6
- PyVmomi
options:
  state:
    description:
    - Specify state of the floppy disk be in.
    - If C(state) is set to C(present) and VM exists, ensure the VM configuration conforms to task arguments.
    default: present
    choices: [ present, absent ]
  name:
    description:
    - Name of the VM to work with.
    - VM names in vCenter are not necessarily unique, which may be problematic, see C(name_match).
    - This parameter is case sensitive.
    required: yes
  name_match:
    description:
    - If multiple VMs matching the name, use the first or last found.
    default: 'first'
    choices: [ first, last ]
  uuid:
    description:
    - UUID of the instance to manage if known, this is VMware's unique identifier.
    - This is required if name is not supplied.
  type:
    description:
    - The type of floppy, valid options are C(none), C(client) or C(flp).
    - With C(none) the floppy will be disconnected but present.
    default: none
    choices: [ none, client, flp ]
  image_file:
    description:
    - The datastore path to the flp file to use, in the form of C([datastore1] path/to/file.flp). 
    - Required if type is set C(flp).
  start_connected:
    description:
    - The datastore path to the flp file to use, in the form of C([datastore1] path/to/file.flp). 
  esxi_hostname:
    description:
    - The ESXi hostname where the virtual machine will run.
    - This parameter is case sensitive.
  datacenter:
    description:
    - Destination datacenter for the deploy operation.
    - This parameter is case sensitive.
    default: ha-datacenter
extends_documentation_fragment: vmware.documentation

author:
    - Helvio Junior - M4v3r1ck (@helviojunior)
'''

EXAMPLES = r'''
- name: Add/edit an empty floppy drive
  helviojunior.vmware.vmware_guest_floppy:
    hostname: 10.0.1.20
    username: administrator@vsphere.local
    password: vmware
    validate_certs: no
    type: none
  delegate_to: localhost

- name: Add/edit client connected floppy drive
  helviojunior.vmware.vmware_guest_floppy:
    hostname: 10.0.1.20
    username: administrator@vsphere.local
    password: vmware
    validate_certs: no
    type: client
  delegate_to: localhost

- name: Add/edit .flp file floppy drive
  helviojunior.vmware.vmware_guest_floppy:
    hostname: 10.0.1.20
    username: administrator@vsphere.local
    password: vmware
    validate_certs: no
    type: flp
    image_file: "[datastore1] base_new.flp"
    start_connected: true
  delegate_to: localhost

- name: Remove floppy drive
  helviojunior.vmware.vmware_guest_floppy:
    hostname: 10.0.1.20
    username: administrator@vsphere.local
    password: vmware
    validate_certs: no
    state: absent
  delegate_to: localhost
  
'''

RETURN = r'''
instance:
    description: metadata about the virtual machine
    returned: always
    type: dict
    sample: None
'''

HAS_KNOWSMORE = False
try:
    import knowsmore
    from knowsmore.cmd.wordlist import WordList
    from knowsmore.util.tools import Tools

    HAS_KNOWSMORE = True
except ImportError:
    pass

import random
import string

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_native

class AdHelper():

    _USER = string.ascii_uppercase + string.digits
    _PASS_SIMPLE = string.ascii_lowercase + string.ascii_uppercase + string.digits
    _PASS_COMPLEX = _PASS_SIMPLE + string.punctuation

    def __init__(self, module):
        self.module = module
        self.users = []
        self.groups = []
        self.ous = []
        self.spn = []
        self.wl = list()

    def get_name(self, prefix: str = 'U') -> str:
        return "%s%s" % (prefix, ''.join(random.choice(self._USER) for i in range(10)))

    def get_user_data(self, complex=False, groups=[]):

        name = self.get_name()
        passwd = ''.join(random.choice(self._PASS_SIMPLE) for i in range(8))
        has_wl = len(self.wl) > 0

        if complex:
            passwd = ''.join(random.choice(self._PASS_SIMPLE) for i in range(12))
        elif has_wl and random.randint(1, 500) % 3 == 0:
            passwd = random.choice(self.wl)

        return dict(
            name=name,
            member_of=groups + [random.choice(self.groups)],
            ou=random.choice(self.ous),
            passwd=passwd
        )

    def get_spn(self, username):
        return dict(
            name=username,
            spn=f"MSSQLSvc/fakespn.{username.lower()}.local:1433"
        )

    def calculate(self):
        result = {'failed': False, 'changed': False}

        name = self.module.params.get('company_name', None)
        if name:

            wlc = WordList()
            wlc.small = False
            wlc.name = name
            wlc.max_size = len(wlc.name) + 5
            wlc.min_size = 5
            wlc.setup()
            estimated_size = wlc.calculate()
            max = 512 * 1024 # 1 GB
            if estimated_size > max:
                wlc.small = True
                estimated_size = wlc.calculate()

            if estimated_size > max:
                self.module.fail_json(
                    msg=(f"This wordlist will generate +- the following amount of "
                         f"data {Tools.sizeof_fmt(estimated_size, start_unit='K')}."
                                           f"The maximum is {Tools.sizeof_fmt(max, start_unit='K')}"))

            self.wl = [w for w in wlc.generate(wlc.name, 0)]
            self.wl.append(wlc.name.lower())
            self.wl.append(wlc.name.upper())

        self.groups = [self.get_name(prefix='G') for _ in range(self.module.params.get('group', 1))]
        self.ous = [self.get_name(prefix='OU') for _ in range(self.module.params.get('ou', 1))]

        self.users = [self.get_user_data() for _ in range(
            self.module.params.get('user', 1) - self.module.params.get('domain_admins', 1))]

        das = [self.get_user_data(complex=random.randint(1, 10) % 2 == 0, groups=['Domain Admins']) for _ in range(
            self.module.params.get('domain_admins', 1))]

        self.users += das

        self.spn = [self.get_spn(random.choice(self.users).get('name', None)) for _ in range(self.module.params.get('spn', 1))]

        # Try to import another module
        result = {'failed': False, 'changed': True,
                  'data': dict(
                      group=self.groups,
                      ou=self.ous,
                      spn=self.spn,
                      user=self.users
                  )
                  }

        return result


def main():
    argument_spec = dict(

        company_name=dict(type='str', default=None, required=False),
        user=dict(type='int', default=1),
        group=dict(type='int', default=1),
        ou=dict(type='int', default=1),
        domain_admins=dict(type='int', default=1),
        spn=dict(type='int', default=1),

    )


    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    if module.params.get('user', 1) < 0:
        module.fail_json(msg="The parameter C(user) cannot be less than 1")

    if module.params.get('group', 1) < 0:
        module.fail_json(msg="The parameter C(group) cannot be less than 1")

    if module.params.get('ou', 1) < 0:
        module.fail_json(msg="The parameter C(ou) cannot be less than 1")

    if module.params.get('domain_admins', 1) < 0:
        module.fail_json(msg="The parameter C(domain_admins) cannot be less than 1")

    if module.params.get('spn', 1) < 0:
        module.fail_json(msg="The parameter C(spn) cannot be less than 1")

    ad = AdHelper(module)
    result = ad.calculate()

    if 'failed' not in result:
        result['failed'] = False

    if result['failed']:
        module.fail_json(**result)
    else:
        module.exit_json(**result)


if __name__ == '__main__':
    main()
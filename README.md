# Creating a new Active Directory Forest with Ansible

* [x] Active Directory Forest
* [x] Users
* [x] Groups
* [x] OUs
* [x] SPNs

## Installing

```bash
pip install netaddr
ansible-galaxy collection install community.windows
```

## Executing

```bash
ansible-playbook -i localhost, deploy_ad.yaml
```

### Populate AD

If you want populate your brand new AD with random data, execute the command bellow

```bash
ansible-playbook -i localhost, deploy_ad_data.yaml
```

## Deploy Windows Machine from scratch

- [How to build a Windows VM from scratch with Ansible](https://github.com/helviojunior/ansible-vmware-windows)

## Common error

```
objc[7453]: +[__NSCFConstantString initialize] may have been in progress in another thread when fork() was called.
objc[7453]: +[__NSCFConstantString initialize] may have been in progress in another thread when fork() was called. We cannot safely call it or ignore it in the fork() child process. Crashing instead. Set a breakpoint on objc_initializeAfterForkError to debug.
```

To solve this error run
```bash
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

## Inspiration
- [Creating a new Active Directory Forest with Ansible](https://madlabber.wordpress.com/2019/09/08/creating-a-new-active-directory-forest-with-ansible/)

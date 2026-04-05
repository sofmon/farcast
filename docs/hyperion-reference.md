# Hyperion Reference

The FarCast technology stack draws its naming from Dan Simmons' *Hyperion Cantos* — a science fiction saga spanning four novels set across centuries of human civilisation among the stars. The naming is not cosmetic. Each component's behaviour is intentionally designed to reflect its namesake's role in the story.

---

## The Source Material

In the *Hyperion Cantos*, humanity has spread across hundreds of worlds connected by **farcaster portals** — doorways that allow instantaneous travel between planets. Step through a portal on one world and emerge on another, light-years away, without delay. The technology is so seamless that some homes have rooms on different planets, connected by farcaster doorways in the hallway.

This is the core metaphor for FarCast: your environment exists in the cloud, but you step into it as if it were local. The distance — and the infrastructure — disappears.

---

## Component Origins

### FarCast

**In the books:** Farcasters are the portal network itself — the technology that collapses distance. They are ubiquitous, invisible infrastructure that everyone depends on but few understand.

**In the OS:** FarCast is the operating system — the invisible layer that makes cloud infrastructure feel like a local machine. You don't think about the cloud provider, the region, or the networking. You just farcast it.

### TechnoCore

**In the books:** The TechnoCore is the hidden artificial intelligence collective that secretly built and maintained the farcaster network. It operates behind the scenes, making decisions and managing the infrastructure that humanity relies on — without humanity fully understanding its role or its motives.

**In the OS:** TechnoCore is the kernel. It orchestrates everything: instance lifecycle, application scheduling, and adaptive resource management. It monitors running applications and adjusts CPU, memory, and replicas based on observed behaviour. Like its namesake, it works behind the scenes — applications don't need to know it exists.

### Planck

**In the books:** Planck space (also called the Planck dimension or the Void Which Binds) is the quantum substrate through which farcasters operate. It is the medium that makes instantaneous travel possible — the layer beneath visible reality where the actual work happens.

**In the OS:** Planck is the compute abstraction layer. It sits between FarCast and the underlying managed Kubernetes services (EKS, GKE, AKS), translating application requirements into cloud-native workloads. Like Planck space, it is the invisible medium where execution actually occurs.

### FatLine

**In the books:** The fatline is a faster-than-light communication system used when farcaster portals are unavailable. It is the fallback — the way to maintain connection across vast distances when the primary network is down. All communication through it is encrypted and private by necessity, as interception across interstellar distances is a serious threat.

**In the OS:** FatLine is the sole networking layer. All traffic — instance-to-instance, instance-to-internet, and client-to-instance — flows through FatLine. It acts as router, proxy, and encryption boundary in one. Like the fatline in the books, it ensures communication remains private regardless of the hostile environment it traverses.

### DataSphere

**In the books:** The datasphere is the planetary information network — a vast repository of all human knowledge, art, and history, accessible from any world in the Hegemony. It is the collective memory of civilisation, stored and retrieved seamlessly.

**In the OS:** DataSphere is the storage abstraction layer. It proxies all file storage and retrieval, hiding the underlying cloud provider (S3, GCS, or any object store) behind a uniform interface. Like the datasphere in the books, it provides seamless access to stored information — but with one critical addition: everything is encrypted before it leaves the instance. The cloud provider only ever holds encrypted blobs.

### Shrike

**In the books:** The Shrike is the unstoppable guardian of the Time Tombs — a terrifying, blade-covered entity that exists outside normal time. It does not build walls or create barriers. It simply appears when a line has been crossed, and its intervention is absolute. Across all four novels, the Shrike is the one force that cannot be reasoned with, bribed, or circumvented. It enforces the rules of its domain without exception.

**In the OS:** Shrike is the security monitor and policy enforcer. It does not control the network boundary (that is FatLine's role) — instead, it inspects traffic flowing through FatLine and monitors activity within the instance. When policy is violated, Shrike intervenes. Like its namesake, it is not the wall — it is what happens when you breach the wall.

### AllThing

**In the books:** The AllThing is the democratic forum of the Hegemony — a virtual assembly where every citizen can connect, participate, and have their voice heard in collective decision-making. It is the shared intelligence of civilisation, a place where individual minds come together to form something greater.

**In the OS:** AllThing is the AI abstraction layer. It provides a uniform interface over cloud AI services — Gemini, Claude, OpenAI, or any provider the operator chooses. Applications access AI capabilities through AllThing via the SDK, never directly through a provider. Initially it surfaces as a chat interface in FarSight, but it evolves into the AI backbone of the entire system — powering TechnoCore's adaptive resource management, Shrike's traffic analysis, and any application that needs intelligence. Like its namesake, AllThing is where individual components come together to access collective intelligence.

### FarSight

**In the books:** While not a named technology in the original novels, the concept of "seeing through" a farcaster — observing what lies on the other side before stepping through — is woven throughout the Cantos. The farcaster portals are not blind doorways; operators and the TechnoCore can observe and monitor what passes through them.

**In the OS:** FarSight is the UX layer — how users see into and interact with their FarCast instance. The downloadable "farcast" app is FarSight, providing a tiling browser interface where each tile is an application running inside the instance. True to the metaphor, FarSight lets you look through the portal and interact with the world on the other side.

---

## Future Concepts

### TimeTomb

**In the books:** The Time Tombs are mysterious structures on the planet Hyperion that move backwards through time. They are sealed artifacts, immune to the passage of time, containing preserved states from the future. They cannot be altered, only opened when the time is right.

**In the OS (future):** TimeTomb will provide point-in-time snapshots of an entire FarCast instance — state, configuration, and DataSphere volumes — allowing operators to freeze, restore, and clone instances. Like the Time Tombs, a TimeTomb snapshot is a sealed artifact: an immutable record of an instance at a specific moment.

---

*"The farcasters. Humanity's greatest achievement and deepest dependency."*
— paraphrased from the Hyperion Cantos

---

← Back to [Sofmon FarCast README](../README.md)

// Cloud Security Questions - 50 Items
const cloudData = [
    {
        id: "cloud_1",
        question: "What's the difference between IaaS, PaaS, and SaaS? Give an example of each.",
        answer: "IaaS (Infrastructure as a Service) provides virtualized computing resources like EC2, where you manage the OS and applications. PaaS (Platform as a Service) provides a development platform like AWS Lambda or Google App Engine, where you only manage your application code. SaaS (Software as a Service) provides complete applications like Office 365 or Salesforce, where the provider manages everything and you just use the software through a web interface."
    },
    {
        id: "cloud_2",
        question: "What's the shared responsibility model in cloud security?",
        answer: "The shared responsibility model divides security responsibilities between the cloud provider and customer, where the provider secures the infrastructure 'of' the cloud (physical security, hypervisor, network controls) while the customer secures everything 'in' the cloud (data, applications, operating systems, network configuration). The division point varies by service type: IaaS requires more customer responsibility, while SaaS shifts more responsibility to the provider. Understanding this model is crucial for implementing proper security controls and avoiding coverage gaps."
    },
    {
        id: "cloud_3",
        question: "What's the difference between cloud regions and availability zones?",
        answer: "Regions are geographically separate areas containing multiple data centers, designed to provide low latency to users in that geographic area and comply with local data sovereignty requirements. Availability Zones (AZs) are isolated data centers within a region, each with independent power, cooling, and networking, connected through high-bandwidth, low-latency links. AZs provide fault tolerance within a region, while multiple regions provide geographic redundancy and disaster recovery capabilities."
    },
    {
        id: "cloud_4",
        question: "Why is multi-tenancy a risk in cloud environments?",
        answer: "Multi-tenancy means multiple customers share the same physical infrastructure, creating risks of data leakage between tenants, side-channel attacks that exploit shared resources, and potential for one tenant's security incident to affect others. Malicious tenants could potentially exploit hypervisor vulnerabilities or resource contention to access other tenants' data. Cloud providers implement strong isolation mechanisms, but the shared infrastructure inherently creates attack surfaces that don't exist in dedicated environments."
    },
    {
        id: "cloud_5",
        question: "What's the difference between public, private, hybrid, and multi-cloud?",
        answer: "Public cloud uses shared infrastructure provided by third parties like AWS or Azure, offering cost efficiency but less control. Private cloud uses dedicated infrastructure (on-premises or hosted) providing more control and security but higher costs. Hybrid cloud combines public and private clouds, allowing data and applications to move between them for flexibility and optimization. Multi-cloud uses multiple public cloud providers to avoid vendor lock-in, improve resilience, and leverage best-of-breed services."
    }
];

module.exports = cloudData;

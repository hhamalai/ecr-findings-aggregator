<template>
    <div>
        <h3>{{ region.region }}</h3>
        <div v-for="repository in region.repositories"
             v-bind:key="repository.name">
            <Repository v-bind:repository="repository"  v-bind:selected_cve=selected_cve></Repository>
        </div>
    </div>
</template>

<script>
    import Repository from "./Repository";

    export default {
        name: 'Region',
        components: {
            Repository
        },
        props: ['region', 'selected_cve'],
    }
</script>
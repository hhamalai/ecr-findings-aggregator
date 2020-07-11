<template>
    <div>
        <h4>{{ repository.name }}</h4>
        <ContainerImage v-bind:selected_cve=selected_cve v-bind:image=image
                        v-for="image in repository.images"
                        v-bind:key="image.digest+image.tag">

        </ContainerImage>
    </div>
</template>

<script>
    import ContainerImage from "./ContainerImage";
    function image_count() {
        if (this.repository.images != null) {
            return this.repository.images.length
        } else {
            return 0
        }
    }

    export default {
        name: 'Repository',
        components: {
            ContainerImage
        },
        props: ['repository', 'selected_cve'],
        computed: {
            image_count: image_count,
        }
    }
</script>